//! Shared receiver restart through a protected, bounded key-to-file catalog.
//! The existing SDK owns mTLS, routing, WAL barriers, revalidation and joins.
//! This adapter owns persistent claims, all-session disk admission and retirement.

use super::{Options, Retention, RevocationPolicy, CONTROL_TICK, completion_event, deadline, key_json, snapshot_json};
use super::super::journal_catalog::{Catalog, Entry, FilePolicy, Retirement};
use super::super::settings::{self, ServeConfig, invalid};
use super::super::{INBOX_OWNERSHIP, emit, receipt_json, runtime, storage};
use asupersync::Cx;
use asupersync::net::atp::sdk::NativeClientAuthorization;
use asupersync::net::atp::sdk::native_auth::live::{LiveStreamError, LiveStreamReceiver};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::{RESUMABLE_LIVE_ALPN, ResumeError};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::{ReceiverCheckpoint, ReceiverCheckpointPhase};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::file::{ReceiverJournalFile, ReceiverJournalObserver};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::service::{ResumableService, ResumeServiceCompletion, ResumeServiceOutcome, ResumeServiceConfig, ResumeSessionKey, ResumeSessionStatus};
use asupersync::runtime::spawn_blocking_io;
use asupersync::types::CancelReason;
use clap::Args;
use parking_lot::Mutex;
use serde_json::{Value, json};
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::collections::BTreeMap;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Limits for each NEW journal. Existing entries retain their original ceilings.
#[derive(Args, Clone, Copy, Debug)]
pub(in super::super) struct JournalOptions {
    #[arg(long)]
    journal_snapshots: u32,
    #[arg(long)]
    journal_bytes: u64,
}
impl JournalOptions {
    fn policy(self, maximum: u64) -> io::Result<FilePolicy> {
        let policy = FilePolicy { data_bytes: maximum, journal_bytes: self.journal_bytes, snapshots: self.journal_snapshots };
        policy.validate()?;
        Ok(policy)
    }
}

// Deliberately retain the catalog lock through uncertain runtime teardown.
static CATALOG_OWNERSHIP: OnceLock<Arc<Catalog>> = OnceLock::new();
#[derive(Clone)]
struct Tracked { entry: Entry, observer: ReceiverJournalObserver }
type Observers = Arc<Mutex<BTreeMap<ResumeSessionKey, Tracked>>>;

/// Reserve growth for every restorable entry, not just currently connected ones.
/// The ordinary locked inventory already counts existing entries and bytes.
fn reserve_restored(catalog: &Catalog, inboxes: &storage::Inboxes, maximum: u64) -> io::Result<()> {
    for entry in catalog.entries() {
        if entry.retired.is_some() { continue; }
        let Some(inbox) = inboxes.get(&entry.key.client) else { continue; };
        let metadata = std::fs::symlink_metadata(&inbox.directory)?;
        if (metadata.dev(), metadata.ino()) != entry.directory {
            return Err(invalid("catalog client inbox cannot be remapped"));
        }
        if entry.policy.data_bytes > maximum {
            return Err(invalid("catalog entry exceeds current transfer ceiling"));
        }
        let path = entry.data_path(&inbox.directory);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid("catalog data must remain a private original file"));
        }
        // Conservative even for a short committed file until its key is retired.
        // Missing pairs can never grow: the factory only reopens, never recreates.
        inbox.reserve_private_file(entry.policy.data_bytes, Some(metadata.len()))?;
    }
    Ok(())
}

pub(in super::super) fn serve(
    config: ServeConfig, options: Options, journal_options: JournalOptions,
    path: PathBuf, revocations: Option<PathBuf>,
) -> io::Result<()> {
    let limits = options.config(config.max_connections)?;
    let policy = journal_options.policy(config.max_transfer_bytes)?;
    if !(1..=86_400).contains(&config.shutdown_grace_secs) {
        return Err(invalid("shutdown grace must be 1..=86400 seconds"));
    }
    let profile = settings::profile(config.schema_version, config.workers, config.epoch_bytes,
        config.max_transfer_bytes, config.operation_timeout_secs)?;
    let ids = config.clients.iter().map(|client| settings::selector(&client.certificate_sha256))
        .collect::<io::Result<Vec<_>>>()?;
    let authorization = NativeClientAuthorization::new(settings::roots(&config.client_ca)?, ids.iter().copied())
        .map_err(|_| invalid("invalid journaled receiver authorization"))?;
    let authority = settings::sdk(u32::try_from(limits.max_sessions).map_err(|_| invalid("session count overflow"))?, &profile)?
        .live_stream_receiver(profile, settings::identity(&config.identity)?, authorization.clone())
        .map_err(|_| invalid("invalid authenticated journaled receiver"))?;
    let catalog = Catalog::open(&path)?;
    let root = std::fs::canonicalize(catalog.parent())?;
    for client in &config.clients {
        let inbox = std::fs::canonicalize(&client.directory)?;
        if root.starts_with(&inbox) || inbox.starts_with(&root) {
            return Err(invalid("catalog and inbox directory trees must be disjoint"));
        }
    }
    let mut revocation_policy = None;
    if let Some(path) = revocations {
        let parent = std::fs::canonicalize(path.parent().ok_or_else(|| invalid("policy parent required"))?)?;
        if parent.starts_with(&root) { return Err(invalid("revocation policy must be outside the dedicated catalog directory")); }
        for client in &config.clients {
            if parent.starts_with(std::fs::canonicalize(&client.directory)?) {
                return Err(invalid("revocation policy must be outside all inboxes"));
            }
        }
        revocation_policy = Some(RevocationPolicy::open(path, ids, authorization)?);
    }
    CATALOG_OWNERSHIP.set(Arc::clone(&catalog))
        .map_err(|_| io::Error::other("foreground process already owns a receiver catalog"))?;
    let inboxes = Arc::new(storage::load(&config.clients)?);
    INBOX_OWNERSHIP.set(Arc::clone(&inboxes))
        .map_err(|_| io::Error::other("foreground process already owns inboxes"))?;
    reserve_restored(&catalog, &inboxes, config.max_transfer_bytes)?;
    let signals = if revocation_policy.is_some() { Signals::new([SIGINT, SIGTERM, SIGHUP])? }
        else { Signals::new([SIGINT, SIGTERM])? };
    runtime(config.workers, serve_loop(config, options, limits, policy, authority, catalog, inboxes, signals, revocation_policy))?;
    emit(json!({"schema_version": 1, "event": "stopped", "mode": "shared_journaled", "drained": true}))
}

async fn serve_loop(
    config: ServeConfig, options: Options, limits: ResumeServiceConfig, policy: FilePolicy,
    authority: LiveStreamReceiver, catalog: Arc<Catalog>, inboxes: Arc<storage::Inboxes>,
    mut signals: Signals, mut revocations: Option<RevocationPolicy>,
) -> io::Result<()> {
    let cx = Cx::current().ok_or_else(|| io::Error::other("missing shared journal context"))?;
    let scope = cx.scope();
    let tracked: Observers = Arc::new(Mutex::new(BTreeMap::new()));
    let factory_catalog = Arc::clone(&catalog);
    let factory_tracked = Arc::clone(&tracked);
    let factory = move |_: Cx, key: ResumeSessionKey| {
        let catalog = Arc::clone(&factory_catalog);
        let tracked = Arc::clone(&factory_tracked);
        let inbox = inboxes.get(&key.client).cloned();
        async move {
            let inbox = inbox.ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
            let (entry, journal) = spawn_blocking_io(move || {
                // Durable catalog admission is BEFORE quota and create-only files.
                // A prior key cannot fall back from reopen into create_new.
                let (entry, fresh) = catalog.admit(key, &inbox.directory, policy)?;
                let wal = catalog.wal_path(&entry);
                let data = entry.data_path(&inbox.directory);
                let journal = if fresh {
                    inbox.reserve_private_file(entry.policy.data_bytes, None)?;
                    ReceiverJournalFile::create_new(&wal, &data, entry.policy.limits())?
                } else {
                    // All retained growth was charged before listener readiness.
                    ReceiverJournalFile::open_existing(&wal, &data)?
                };
                Ok((entry, journal))
            }).await?;
            let observed = Tracked { entry, observer: journal.observer() };
            {
                let mut map = tracked.lock();
                if map.contains_key(&key) { return Err(io::Error::other("duplicate catalog factory ownership")); }
                map.insert(key, observed);
            }
            journal.into_service_session().await
        }
    };
    let mut service = authority.bind_resumable_service::<_>(&cx, config.bind, limits).await
        .map_err(|_| io::Error::other("journaled shared listener could not bind"))?;
    if let Some(policy) = &revocations { policy.install(&mut service)?; }
    emit(json!({"schema_version": 1, "event": "ready", "mode": "shared_journaled",
        "address": service.local_addr(), "pid": std::process::id(),
        "profile": String::from_utf8_lossy(RESUMABLE_LIVE_ALPN), "atomic_publication": false,
        "partial_restoration": true, "session_preallocated": false,
        "maximum_catalog_keys": catalog.maximum_keys(), "maximum_total_journal_bytes": catalog.maximum_wal(),
        "max_connections": limits.max_connections, "max_sessions": limits.max_sessions,
        "revocation_generation": revocations.as_ref().map(RevocationPolicy::generation)}))?;
    let mut retention = BTreeMap::new();
    let mut stopping = None;
    let mut cancelling = false;
    let mut failure = None;
    let mut output_open = true;
    loop {
        let now = cx.now().as_nanos();
        let mut reload = false;
        for signal in signals.pending() {
            if signal == SIGHUP { reload = true; continue; }
            if stopping.is_none() { service.stop_accepting(); stopping = Some(now); }
            else if !cancelling {
                service.cancel(CancelReason::user("shared journal repeated shutdown signal")); cancelling = true;
            }
        }
        if let Some(reason) = cx.cancel_reason() {
            service.cancel(reason); stopping.get_or_insert(now); cancelling = true;
        }
        if catalog.failed() && failure.is_none() {
            failure = Some(io::Error::other("receiver catalog persistence is unconfirmed"));
            service.cancel(CancelReason::user("shared journal catalog failed"));
            stopping.get_or_insert(now); cancelling = true;
        }
        if stopping.is_some_and(|start| now >= deadline(start, config.shutdown_grace_secs)) && !cancelling {
            service.cancel(CancelReason::user("shared journal shutdown grace expired")); cancelling = true;
        }
        if stopping.is_none() && reload {
            if let Some(policy) = &mut revocations {
                let event = match policy.reload(&cx, Duration::from_secs(config.operation_timeout_secs), &mut service).await {
                    Ok(event) => event,
                    Err(error) => {
                        policy.fail_closed(&mut service); failure = Some(error); stopping = Some(cx.now().as_nanos()); cancelling = true;
                        json!({"schema_version": 1, "event": "revocation_policy_rejected", "generation": policy.generation(), "admission_closed": true, "drained": false})
                    }
                };
                if let Err(error) = emit(event) {
                    output_open = false; failure.get_or_insert(error); policy.fail_closed(&mut service);
                    stopping.get_or_insert(now); cancelling = true;
                }
            }
        }
        if stopping.is_none() {
            let due: Vec<_> = retention.iter().filter_map(|(key, retained): (&ResumeSessionKey, &Retention)| {
                if service.session_status(key) != Some(ResumeSessionStatus::Idle) { return None; }
                if service.is_client_revoked(&key.client) { Some((*key, Retirement::Revoked)) }
                else { retained.expired(now).map(|reason| (*key, expiry_reason(reason))) }
            }).collect();
            for (key, reason) in due {
                if let Err(error) = retire(&catalog, &mut service, &tracked, &mut retention, key, reason, output_open).await {
                    failure.get_or_insert(error);
                    service.cancel(CancelReason::user("shared journal retirement failed"));
                    stopping.get_or_insert(now); cancelling = true; break;
                }
            }
        }
        let next = if stopping.is_some() {
            match asupersync::time::timeout(cx.now(), CONTROL_TICK, service.drain_next()).await {
                Ok(completion) => completion, Err(_) => continue,
            }
        } else {
            match asupersync::time::timeout(cx.now(), CONTROL_TICK, service.next_journaled(&cx, &scope, factory.clone())).await {
                Ok(Ok(completion)) => completion,
                Err(_) => continue,
                Ok(Err(_)) => {
                    failure.get_or_insert_with(|| io::Error::other("shared journal service admission failed"));
                    service.cancel(CancelReason::user("shared journal service failed"));
                    stopping.get_or_insert(now); cancelling = true; continue;
                }
            }
        };
        let Some(completion) = next else { break; };
        let observation = completion.session.and_then(|key| tracked.lock().get(&key).cloned());
        let event = journal_event(&completion, observation.as_ref());
        if output_open {
            if let Err(error) = emit(event) {
                output_open = false; failure.get_or_insert(error);
                service.cancel(CancelReason::user("shared journal output failed"));
                stopping.get_or_insert(now); cancelling = true;
            }
        }
        if let Some(key) = completion.session {
            let reason = retirement(&service, &mut retention, &completion, observation.as_ref(), cx.now().as_nanos(), options);
            // Graceful shutdown preserves valid partial sessions for restart.
            // Terminal local/initialization failures still need durable denial.
            if let Some(reason) = reason.filter(|reason| stopping.is_none()
                || matches!(reason, Retirement::LocalFailure | Retirement::Initialization)) {
                if let Err(error) = retire(&catalog, &mut service, &tracked, &mut retention, key, reason, output_open).await {
                    failure.get_or_insert(error);
                    service.cancel(CancelReason::user("shared journal retirement failed"));
                    stopping.get_or_insert(now); cancelling = true;
                }
            }
        }
    }
    if !service.is_drained() || authority.active_streams() != 0 {
        return Err(io::Error::other("shared journal returned before draining"));
    }
    tracked.lock().clear(); // Weak observation entries only, never files/history.
    match failure { Some(error) => Err(error), None => Ok(()) }
}

fn expiry_reason(reason: &str) -> Retirement {
    if reason == "proof_recovery_expired" { Retirement::ProofWindow } else { Retirement::Idle }
}
fn retirement<W>(
    service: &ResumableService<W>, retention: &mut BTreeMap<ResumeSessionKey, Retention>,
    completion: &ResumeServiceCompletion, observed: Option<&Tracked>, now: u64, options: Options,
) -> Option<Retirement> {
    let key = completion.session?;
    match service.session_status(&key) {
        Some(ResumeSessionStatus::Active) => None, // A Busy refusal cannot affect its owner.
        Some(ResumeSessionStatus::Idle) => {
            let snapshot = service.session_snapshot(&key)?;
            if service.is_client_revoked(&key.client) { return Some(Retirement::Revoked); }
            if snapshot.failed { return Some(Retirement::LocalFailure); }
            // An original narrower ceiling is retained in its actual checkpoint.
            let ceiling = observed.and_then(|o| o.observer.checkpoint().ok())
                .map_or(options.attempts_per_session, |s| s.maximum_attempts());
            if snapshot.attempts >= ceiling { return Some(Retirement::Attempts); }
            if matches!(&completion.outcome, ResumeServiceOutcome::Transfer(_)) {
                let old = retention.get(&key).copied();
                retention.insert(key, Retention::observe(old, now, snapshot.completed.is_some(), options));
            }
            retention.get(&key).and_then(|r| r.expired(now)).map(expiry_reason)
        }
        Some(ResumeSessionStatus::Retired) => Some(Retirement::Initialization),
        None => {
            // The SDK drops its last idle owner when a drain completes. Preserve
            // terminal failure refusal even when its snapshot no longer exists.
            // An I/O error here cannot be attributed back to network versus sink,
            // so conservatively refuse this key rather than assume no local error.
            match &completion.outcome {
                ResumeServiceOutcome::JoinFailed(_) => Some(Retirement::Initialization),
                ResumeServiceOutcome::Rejected(super::ResumeServiceRejection::Factory(_)) => Some(Retirement::Initialization),
                ResumeServiceOutcome::Transfer(report) => match &report.outcome {
                    Err(ResumeError::LocalFailure)
                    | Err(ResumeError::Transfer(LiveStreamError::Io(_) | LiveStreamError::Commit(_))) => Some(Retirement::LocalFailure),
                    Err(ResumeError::ReceiverJournal(error)) if error.source.is_some() => Some(Retirement::LocalFailure),
                    _ => None,
                },
                _ => None,
            }
        }
    }
}
async fn retire<W>(
    catalog: &Arc<Catalog>, service: &mut ResumableService<W>, tracked: &Observers,
    retention: &mut BTreeMap<ResumeSessionKey, Retention>, key: ResumeSessionKey,
    reason: Retirement, output_open: bool,
) -> io::Result<()> {
    if service.session_status(&key) == Some(ResumeSessionStatus::Active) {
        return Err(io::Error::other("cannot retire an active catalog session"));
    }
    let owner = Arc::clone(catalog);
    // Do not abandon this write or release the sink underneath it. This is a
    // started bounded append, not an attempt whose timeout can mean rollback.
    let persisted = spawn_blocking_io(move || owner.retire(key, reason)).await?;
    let observation = tracked.lock().remove(&key);
    let durable = observation.as_ref().map(observation_json);
    let snapshot = if service.session_status(&key) == Some(ResumeSessionStatus::Idle) {
        service.retire(&key).map_err(|_| io::Error::other("idle journal retirement refused"))?
    } else { service.session_snapshot(&key).cloned() };
    retention.remove(&key);
    if output_open {
        emit(json!({"schema_version": 1, "event": "journal_session_retired", "session": key_json(key),
            "reason": reason.label(), "catalog_retirement_appended": persisted,
            "snapshot": snapshot.as_ref().map(snapshot_json), "journal": durable,
            "files_retained": true, "sender_receipt_observed": false}))?;
    }
    Ok(())
}
fn checkpoint_json(saved: &ReceiverCheckpoint) -> Value {
    let phase = match saved.phase() {
        ReceiverCheckpointPhase::Receiving => "receiving",
        ReceiverCheckpointPhase::Finalizing => "finalizing",
        ReceiverCheckpointPhase::Committed => "committed",
        _ => "unknown",
    };
    json!({"phase": phase, "prefix_bytes": saved.prefix().bytes, "pending_bytes": saved.pending_bytes(),
        "attempts": saved.attempts(), "attempt_limit": saved.maximum_attempts(),
        "durable_receipt": saved.committed_receipt().as_ref().map(receipt_json)})
}
fn observation_json(observed: &Tracked) -> Value {
    let (status, saved) = match observed.observer.checkpoint() {
        Ok(saved) => ("observed", Some(checkpoint_json(&saved))),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => ("unavailable_or_busy", None),
        Err(error) if error.kind() == io::ErrorKind::NotConnected => ("owner_released", None),
        Err(_) => ("persistence_unconfirmed", None),
    };
    json!({"catalog_id": observed.entry.id, "status": status, "checkpoint": saved,
        "atomic_publication": false, "data_visibility": "private_in_place"})
}
fn journal_event(completion: &ResumeServiceCompletion, observed: Option<&Tracked>) -> Value {
    let mut event = completion_event(completion, None);
    event["event"] = json!("journal_completion");
    event["journal"] = observed.map(observation_json).unwrap_or(Value::Null);
    event["atomic_publication"] = json!(false);
    if let ResumeServiceOutcome::Transfer(report) = &completion.outcome {
        if let Err(ResumeError::ReceiverJournal(error)) = &report.outcome {
            event["transfer"]["status"] = json!("journal_blocked");
            event["transfer"]["persistence"] = json!({"stored": error.stored,
                "storage_failed": error.source.is_some(),
                "storage_full": error.source.as_ref().is_some_and(|e| e.kind() == io::ErrorKind::StorageFull),
                "interrupted": error.interruption.is_some()});
        }
    }
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::{Cli, Command};
    use clap::Parser;

    #[test]
    fn shared_journal_cli_requires_explicit_catalog_and_storage_budgets() {
        let args = ["atpd-live", "serve-journaled", "--config", "receiver.json", "--catalog", "/state/catalog",
            "--max-sessions", "2", "--max-sessions-per-client", "1", "--max-session-keys", "8",
            "--attempts-per-session", "8", "--journal-snapshots", "32", "--journal-bytes", "65536"];
        assert!(matches!(Cli::try_parse_from(args).unwrap().command, Command::ServeJournaled { .. }));
        assert!(Cli::try_parse_from(&args[..args.len() - 2]).is_err());
        assert!(JournalOptions { journal_snapshots: 0, journal_bytes: 65536 }.policy(64).is_err());
        assert!(JournalOptions { journal_snapshots: 32, journal_bytes: 128 * 1024 * 1024 + 1 }.policy(64).is_err());
        assert!(JournalOptions { journal_snapshots: 32, journal_bytes: 65536 }.policy(0).is_ok());
    }

    #[test]
    fn restart_reserves_growth_for_disconnected_sessions_before_new_admission() {
        let root = tempfile::tempdir().unwrap().keep();
        let state = root.join("state"); let inbox = root.join("inbox");
        for path in [&state, &inbox] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = state.join("catalog"); Catalog::initialize(&path, 4, 65536).unwrap();
        let catalog = Catalog::open(&path).unwrap();
        let id = settings::selector(&"11".repeat(32)).unwrap();
        let policy = FilePolicy { data_bytes: 64, journal_bytes: 4096, snapshots: 16 };
        let (entry, _) = catalog.admit(ResumeSessionKey { client: id, nonce: [3; 32] }, &inbox, policy).unwrap();
        let data = entry.data_path(&inbox); std::fs::write(&data, b"abc").unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = settings::InboxConfig { certificate_sha256: "11".repeat(32), directory: inbox,
            max_retained_bytes: 64, max_retained_entries: 3 };
        let inboxes = storage::load(&[config]).unwrap();
        reserve_restored(&catalog, &inboxes, 64).unwrap();
        assert_eq!(inboxes[&id].reserve_private_file(1, None).unwrap_err().kind(), io::ErrorKind::StorageFull);
        assert!(reserve_restored(&catalog, &inboxes, 63).is_err());
        assert_eq!(std::fs::read(data).unwrap(), b"abc");
    }
}
