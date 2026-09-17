//! Foreground executable integration for the authenticated live-transfer profile.
//! No legacy daemon listener, PID protocol, RPC, or configuration is enabled.

mod ledger;
mod ledger_sink;
mod resume;
mod sender_checkpoint;
mod settings;
mod shared_resume;
mod storage;

use asupersync::Cx;
use asupersync::fs::File;
use asupersync::net::atp::sdk::NativeClientAuthorization;
use asupersync::net::atp::sdk::native_auth::live::commit::LiveStreamCommitError;
use asupersync::net::atp::sdk::native_auth::live::commit::file::{
    LiveFilePublication, LiveFileSink, LiveFileState,
};
use asupersync::net::atp::sdk::native_auth::live::service::{LiveStreamCompletion, LiveStreamPeer};
use asupersync::net::atp::sdk::native_auth::live::{
    LiveStreamError, LiveStreamReceipt, LiveStreamReceiver, LiveStreamReport,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::types::CancelReason;
use clap::{Parser, Subcommand};
use parking_lot::Mutex;
use rustls::pki_types::ServerName;
use serde_json::{Value, json};
use settings::{SendConfig, ServeConfig, hex, invalid};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "atpd-live",
    version,
    about = "Foreground mTLS live transfer with explicit committed inboxes"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Send one source, persisting EOF intent before requesting final publication.
    SendCheckpointed {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        input: PathBuf,
        /// New private checkpoint file; existing files are never reused or overwritten.
        #[arg(long)]
        checkpoint: PathBuf,
        #[command(flatten)]
        options: sender_checkpoint::Options,
    },
    /// Recover only a previously committed final Proof, without opening a source.
    RecoverProof {
        #[arg(long)]
        config: PathBuf,
        /// Existing complete checkpoint, retained under exclusive ownership.
        #[arg(long)]
        checkpoint: PathBuf,
        #[command(flatten)]
        options: sender_checkpoint::Options,
    },
    /// Shared resumable receiving with durable duplicate suppression across restart.
    ServeDurable {
        #[arg(long)]
        config: PathBuf,
        /// Existing initialized ledger outside all inbox directories; never recreated.
        #[arg(long)]
        session_ledger: PathBuf,
        /// Recover only committed final Proofs after checking saved file bytes.
        #[arg(long)]
        recover_committed: bool,
        #[command(flatten)]
        options: shared_resume::Options,
    },
    /// Provision a new private session ledger without overwriting existing state.
    InitSessionLedger {
        #[arg(long)]
        path: PathBuf,
        /// Persistent lifetime key budget; each key reserves a claim and receipt.
        #[arg(long)]
        max_keys: u32,
    },
    /// Inspect historical claims/receipts while the ledger is exclusively offline.
    InspectSessionLedger {
        #[arg(long)]
        path: PathBuf,
    },
    /// Serve multiple authenticated retained sessions on one reconnect port.
    ServeResumable {
        /// Existing strict receiver settings with per-client private inboxes.
        #[arg(long)]
        config: PathBuf,
        #[command(flatten)]
        options: shared_resume::Options,
    },
    /// Receive into private, quota-bounded inboxes. SIGINT/TERM stop then drain.
    Serve {
        /// Strict version-1 JSON settings; no default or ambient trust fallback.
        #[arg(long)]
        config: PathBuf,
    },
    /// Recover one client-bound transfer while this receiver process stays alive.
    ReceiveResumable {
        /// Existing receiver settings with one client and max_connections=1.
        #[arg(long)]
        config: PathBuf,
        /// Maximum connection attempts, including failed handshakes and idle accepts.
        #[arg(long)]
        attempts: u32,
        /// Delay between attempts; the session is never recreated.
        #[arg(long, default_value_t = 250)]
        retry_delay_ms: u64,
        /// Absolute Proof recovery window after local commit; attempts also bound it.
        #[arg(long, default_value_t = 30)]
        proof_recovery_secs: u64,
    },
    /// Retry eligible network failures using one retained authenticated sender.
    SendResumable {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        input: PathBuf,
        /// Explicit retry permission: 1..=1024 total attempts, never new uploads.
        #[arg(long)]
        attempts: u32,
        #[arg(long, default_value_t = 250)]
        retry_delay_ms: u64,
    },
    /// Send a regular file and require the receiver's exact final Proof.
    Send {
        #[arg(long)]
        config: PathBuf,
        /// Local regular, non-symlink file. Never retried automatically.
        #[arg(long)]
        input: PathBuf,
    },
}

pub fn run() -> io::Result<()> {
    match Cli::parse().command {
        Command::SendCheckpointed {
            config,
            input,
            checkpoint,
            options,
        } => sender_checkpoint::send(settings::load(&config)?, input, checkpoint, options),
        Command::RecoverProof {
            config,
            checkpoint,
            options,
        } => sender_checkpoint::recover(settings::load(&config)?, checkpoint, options),
        Command::ServeDurable {
            config,
            session_ledger,
            recover_committed,
            options,
        } => shared_resume::serve_durable(
            settings::load(&config)?,
            options,
            &session_ledger,
            recover_committed,
        ),
        Command::InitSessionLedger { path, max_keys } => {
            ledger::Ledger::initialize(&path, max_keys)?;
            emit(
                json!({"schema_version": 1, "event": "session_ledger_initialized", "maximum_keys": max_keys}),
            )
        }
        Command::InspectSessionLedger { path } => ledger::inspect(&path),
        Command::Serve { config } => serve(settings::load(&config)?),
        Command::ServeResumable { config, options } => {
            shared_resume::serve(settings::load(&config)?, options)
        }
        Command::Send { config, input } => send(settings::load(&config)?, input),
        Command::ReceiveResumable {
            config,
            attempts,
            retry_delay_ms,
            proof_recovery_secs,
        } => {
            let options = resume::Options::new(attempts, retry_delay_ms, proof_recovery_secs)?;
            resume::receive(settings::load(&config)?, options)
        }
        Command::SendResumable {
            config,
            input,
            attempts,
            retry_delay_ms,
        } => {
            let options = resume::Options::new(attempts, retry_delay_ms, 1)?;
            resume::send(settings::load(&config)?, input, options)
        }
    }
}

/// Bounded one-record output, never arbitrary TLS/sink diagnostic payloads.
fn emit(record: Value) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &record).map_err(io::Error::other)?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

fn runtime<T: Send + 'static>(
    workers: usize,
    future: impl Future<Output = io::Result<T>> + Send + 'static,
) -> io::Result<T> {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread()
            .worker_threads(workers)
            .with_sharded_state(true)
    };
    let runtime = builder
        .blocking_threads(1, workers.max(2))
        .build()
        .map_err(|_| io::Error::other("native runtime startup failed"))?;
    let future: Pin<Box<dyn Future<Output = io::Result<T>> + Send>> = Box::pin(future);
    let result = runtime.block_on(runtime.handle().spawn(future));
    if !runtime.shutdown_timeout(Duration::from_secs(30)) {
        // Do not emit a stopped/success receipt when runtime drain is unconfirmed.
        return Err(io::Error::other(
            "runtime shutdown did not confirm complete drain",
        ));
    }
    result
}

fn serve(config: ServeConfig) -> io::Result<()> {
    let profile = settings::profile(
        config.schema_version,
        config.workers,
        config.epoch_bytes,
        config.max_transfer_bytes,
        config.operation_timeout_secs,
    )?;
    if !(1..=86400).contains(&config.shutdown_grace_secs) {
        return Err(invalid("shutdown grace must be 1..=86400 seconds"));
    }
    let sdk = settings::sdk(config.max_connections, &profile)?;
    // Validate all selectors and TLS material before opening any listener.
    let ids = config
        .clients
        .iter()
        .map(|client| settings::selector(&client.certificate_sha256))
        .collect::<io::Result<Vec<_>>>()?;
    let authorization = NativeClientAuthorization::new(settings::roots(&config.client_ca)?, ids)
        .map_err(|_| invalid("invalid explicit client authorization"))?;
    let receiver = sdk
        .live_stream_receiver(
            profile,
            settings::identity(&config.identity)?,
            authorization,
        )
        .map_err(|_| invalid("invalid authenticated receiver configuration"))?;
    let inboxes = Arc::new(storage::load(&config.clients)?);
    INBOX_OWNERSHIP
        .set(Arc::clone(&inboxes))
        .map_err(|_| io::Error::other("foreground process already owns inboxes"))?;
    let signals = Signals::new([SIGINT, SIGTERM])?;
    let workers = config.workers;
    runtime(workers, serve_loop(config, receiver, inboxes, signals))?;
    emit(json!({"schema_version": 1, "event": "stopped", "drained": true}))
}

// This is a foreground process, not a reusable library owner. Keep each
// exclusive inbox lock until the OS tears down the process, even when runtime
// shutdown cannot confirm that its blocking workers finished. Static storage
// is intentional: returning an error must not open a second writer's admission
// window while an old started filesystem call can still publish.
static INBOX_OWNERSHIP: OnceLock<Arc<storage::Inboxes>> = OnceLock::new();

type Publications = Arc<Mutex<BTreeMap<SocketAddr, LiveFilePublication>>>;

async fn serve_loop(
    config: ServeConfig,
    receiver: LiveStreamReceiver,
    inboxes: Arc<storage::Inboxes>,
    mut signals: Signals,
) -> io::Result<()> {
    let cx = Cx::current().ok_or_else(|| io::Error::other("missing daemon task context"))?;
    let scope = cx.scope();
    let mut service = receiver
        .bind_service(&cx, config.bind, config.max_connections as usize)
        .await
        .map_err(|_| io::Error::other("authenticated listener could not bind"))?;
    let publications: Publications = Arc::new(Mutex::new(BTreeMap::new()));
    let tracked = Arc::clone(&publications);
    let limit = config.max_transfer_bytes;
    let factory = move |child: Cx, peer: LiveStreamPeer| {
        let inbox = inboxes.get(&peer.certificate).cloned();
        let tracked = Arc::clone(&tracked);
        async move {
            let inbox = inbox.ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
            inbox.reserve(limit)?;
            let mut nonce = [0; 16];
            child.random_bytes(&mut nonce);
            let filename = format!("{}.bin", hex(&nonce));
            let sink =
                LiveFileSink::create(&child, inbox.directory.clone(), filename, limit).await?;
            let mut publications = tracked.lock();
            if publications.contains_key(&peer.address) {
                // Never overwrite an earlier worker's uncollected publication.
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "uncollected peer publication",
                ));
            }
            publications.insert(peer.address, sink.publication());
            Ok(sink)
        }
    };
    emit(
        json!({"schema_version": 1, "event": "ready", "address": service.local_addr(),
        "pid": std::process::id(), "profile": "atp-live/1", "application_commit": true,
        "max_connections": config.max_connections, "max_transfer_bytes": config.max_transfer_bytes}),
    )?;

    let mut stopping_at = None;
    let mut cancelling = false;
    let mut failure = None;
    loop {
        // Nonblocking signal collection, with no detached signal worker. The
        // 50 ms timer also guarantees another poll when the listener is idle.
        if signals.pending().next().is_some() {
            if stopping_at.is_none() {
                service.stop_accepting();
                stopping_at = Some(cx.now());
            } else if !cancelling {
                service.cancel(CancelReason::user("atpd-live second shutdown signal"));
                cancelling = true;
            }
        }
        if let Some(start) = stopping_at {
            let elapsed = cx.now().as_nanos().saturating_sub(start.as_nanos());
            if !cancelling
                && elapsed >= Duration::from_secs(config.shutdown_grace_secs).as_nanos() as u64
            {
                service.cancel(CancelReason::user("atpd-live shutdown grace expired"));
                cancelling = true;
            }
        }
        let completion = if stopping_at.is_some() {
            match asupersync::time::timeout(
                cx.now(),
                Duration::from_millis(50),
                service.drain_next(),
            )
            .await
            {
                Ok(completion) => completion,
                Err(_) => continue,
            }
        } else {
            match asupersync::time::timeout(
                cx.now(),
                Duration::from_millis(50),
                service.next_committing(&cx, &scope, factory.clone()),
            )
            .await
            {
                Ok(Ok(completion)) => completion,
                Err(_) => continue,
                Ok(Err(_)) => {
                    failure = Some(io::Error::other("live service admission or context failed"));
                    service.cancel(CancelReason::user("atpd-live service failure"));
                    stopping_at = Some(cx.now());
                    cancelling = true;
                    continue;
                }
            }
        };
        let Some(completion) = completion else {
            break;
        };
        let publication = publications.lock().remove(&completion.address);
        let event = completion_event(&completion, publication.as_ref());
        if failure.is_none()
            && let Err(error) = emit(event)
        {
            // A broken diagnostics pipe is fatal, but it cannot abandon workers.
            failure = Some(error);
            service.cancel(CancelReason::user("atpd-live output failed"));
            stopping_at = Some(cx.now());
            cancelling = true;
        }
    }
    if !service.is_drained() || receiver.active_streams() != 0 {
        return Err(io::Error::other("live service returned without draining"));
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn receipt_json(receipt: &LiveStreamReceipt) -> Value {
    json!({"bytes": receipt.prefix.bytes, "epochs": receipt.prefix.epochs,
        "stream_nonce": hex(&receipt.prefix.stream_nonce), "chain": hex(&receipt.prefix.chain),
        "sha256": hex(&receipt.source_sha256)})
}

fn report_json(report: &LiveStreamReport) -> Value {
    let (status, receipt) = match &report.outcome {
        Ok(receipt) => ("complete", Some(receipt)),
        Err(LiveStreamError::Commit(error)) => match error.as_ref() {
            LiveStreamCommitError::CommittedWithoutProof { receipt, .. } => {
                ("committed_without_proof", Some(receipt.as_ref()))
            }
            LiveStreamCommitError::Unconfirmed { receipt, .. } => {
                ("commit_unconfirmed", Some(receipt.as_ref()))
            }
            _ => ("commit_failed", None),
        },
        Err(LiveStreamError::Cancelled(_)) => ("cancelled", None),
        Err(LiveStreamError::Timeout(_)) => ("timeout", None),
        Err(LiveStreamError::Tls(_) | LiveStreamError::Authentication(_)) => ("tls_failed", None),
        Err(LiveStreamError::TooLarge(_)) => ("size_refused", None),
        Err(LiveStreamError::Io(error)) if error.kind() == io::ErrorKind::StorageFull => {
            ("retention_refused", None)
        }
        Err(_) => ("transfer_failed", None),
    };
    json!({"status": status, "receipt": receipt.map(receipt_json),
        "flushed_prefix_bytes": report.prefix.as_ref().map(|prefix| prefix.bytes),
        "sink_written_bytes": report.sink_written_bytes})
}

fn completion_event(
    completion: &LiveStreamCompletion,
    publication: Option<&LiveFilePublication>,
) -> Value {
    let (peer, transfer) = match &completion.result {
        Ok(session) => (
            session
                .peer
                .as_ref()
                .map(|peer| hex(peer.certificate.as_bytes())),
            report_json(&session.transfer),
        ),
        Err(_) => (None, json!({"status": "join_failed"})),
    };
    let publication = publication.map(|publication| {
        let status = publication.status();
        let state = match status.state {
            LiveFileState::Staged => "staged",
            LiveFileState::Committing => "committing",
            LiveFileState::Published => "published",
            LiveFileState::Durable => "durable",
        };
        json!({"state": state, "error": status.error_kind.is_some(),
            "filename": publication.destination_path().file_name().and_then(|name| name.to_str())})
    });
    json!({"schema_version": 1, "event": "completion", "connection": completion.connection,
        "address": completion.address, "client_certificate_sha256": peer,
        "transfer": transfer, "publication": publication,
        "final_proof_direction": "written_not_peer_acknowledged"})
}

fn send(config: SendConfig, input: PathBuf) -> io::Result<()> {
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
    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|_| invalid("invalid TLS server name"))?;
    let sender = settings::sdk(1, &profile)?
        .live_stream_sender(
            profile,
            server_name,
            settings::roots(&config.server_ca)?,
            settings::identity(&config.identity)?,
        )
        .map_err(|_| invalid("invalid authenticated sender configuration"))?;
    let file = settings::open_regular(&input, false)?;
    if file.metadata()?.len() > config.max_transfer_bytes {
        return Err(invalid("source exceeds transfer limit"));
    }
    runtime(config.workers, async move {
        let cx = Cx::current().ok_or_else(|| io::Error::other("missing sender task context"))?;
        let report = sender
            .send_reader(&cx, config.remote, File::from_std(file))
            .await;
        emit(
            json!({"schema_version": 1, "event": "send_result", "transfer": report_json(&report),
            "final_proof_direction": "received"}),
        )?;
        report.outcome.map(|_| ()).map_err(|_| {
            io::Error::other("send did not receive final peer Proof; no retry was attempted")
        })
    })
}

#[cfg(test)]
mod tests;
