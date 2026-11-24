//! Durable finite uploads through the existing native SDK recovery owner.
//!
//! Checkpoints retain complete plaintext sources in an explicitly selected
//! private directory. Sending after restart uses those retained bytes, not a
//! remote byte offset. A lost acknowledgement remains uncertain until the
//! operator names that exact attempt; there is no automatic retry.

use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::io::Write;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::path::PathBuf;

#[derive(Args)]
#[command(after_help = "Each command prints one JSON report. Checkpoints retain complete source bytes; they do not resume at a remote byte offset. Sending may have committed before an acknowledgement was lost. An explicit retry may publish again, so this is not an exactly-once delivery guarantee. Cancel prevents later local attempts and cannot undo a remote publication. Checkpoint directories and their plaintext payloads are retained.")]
pub(super) struct CheckpointArgs {
    #[command(subcommand)]
    command: CheckpointCommand,
}

#[derive(Subcommand)]
#[cfg_attr(not(all(unix, feature = "tls")), allow(dead_code))]
enum CheckpointCommand {
    /// Retain a complete regular file durably, without contacting the peer.
    Prepare {
        /// Regular source file; symlinks and special files are refused.
        source: PathBuf,
        /// Existing private directory for retained plaintext; protect its ancestry.
        #[arg(long, value_name = "DIRECTORY")]
        spool_dir: PathBuf,
        /// Portable destination filename (defaults to the source filename).
        #[arg(long, value_name = "FILENAME")]
        name: Option<String>,
        #[command(flatten)]
        connection: ConnectionArgs,
    },
    /// Send retained bytes, or return an already saved receipt without networking.
    Send {
        /// Exact checkpoint directory returned by prepare.
        directory: PathBuf,
        /// Accept possible prior delivery for this exact uncertain attempt only.
        #[arg(long, value_name = "ATTEMPT")]
        acknowledge_uncertain_attempt: Option<NonZeroU64>,
        #[command(flatten)]
        connection: ConnectionArgs,
    },
    /// Inspect durable state and saved receipt; does not send or rehash the source.
    Status {
        directory: PathBuf,
        #[command(flatten)]
        connection: ConnectionArgs,
    },
    /// Durably prevent later local sends; cannot undo or abort a remote commit.
    Cancel {
        directory: PathBuf,
        #[command(flatten)]
        connection: ConnectionArgs,
    },
}

#[derive(Args)]
#[cfg_attr(not(all(unix, feature = "tls")), allow(dead_code))]
struct ConnectionArgs {
    /// Expected peer socket address, explicitly rebound on every operation.
    #[arg(long, value_name = "IP:PORT")]
    remote: SocketAddr,
    /// Expected TLS server identity, explicitly rebound on every operation.
    #[arg(long, value_name = "NAME")]
    server_name: String,
    /// Stable local identity label; diagnostic binding, not peer authentication.
    #[arg(long, value_name = "LABEL")]
    peer_id: String,
    /// Explicit PEM trust roots or leaf pins; otherwise use native trust roots.
    #[arg(long, value_name = "PEM")]
    ca: Option<PathBuf>,
    /// Maximum retained source bytes accepted by this invocation.
    #[arg(
        long,
        default_value_t = super::DEFAULT_MAX_TRANSFER_BYTES,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    max_bytes: u64,
    /// Bound each source/protocol wait, not the whole transfer.
    #[arg(
        long,
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(1..=86400)
    )]
    timeout_secs: u64,
    /// Worker threads for this operation.
    #[arg(
        long,
        default_value_t = 2,
        value_parser = clap::value_parser!(u16).range(1..=64)
    )]
    workers: u16,
}

impl CheckpointCommand {
    fn operation(&self) -> &'static str {
        match self {
            Self::Prepare { .. } => "prepare",
            Self::Send { .. } => "send",
            Self::Status { .. } => "status",
            Self::Cancel { .. } => "cancel",
        }
    }

    #[cfg(all(unix, feature = "tls"))]
    fn connection(&self) -> &ConnectionArgs {
        match self {
            Self::Prepare { connection, .. }
            | Self::Send { connection, .. }
            | Self::Status { connection, .. }
            | Self::Cancel { connection, .. } => connection,
        }
    }
}

struct CommandReport {
    value: Value,
    failure: Option<String>,
}

struct Failure {
    code: &'static str,
    message: String,
    details: Value,
}

impl Failure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: Value::Null,
        }
    }

    fn value(&self) -> Value {
        json!({"code": self.code, "message": self.message, "details": self.details})
    }
}

/// Print exactly one JSON result, including failures that retain useful state.
pub(super) fn run(args: CheckpointArgs) -> Result<(), String> {
    let operation = args.command.operation();
    #[cfg(all(unix, feature = "tls"))]
    let result = supported::execute(args.command);
    #[cfg(not(all(unix, feature = "tls")))]
    let result: Result<CommandReport, Failure> = Err(Failure::new(
        "unsupported_platform",
        "durable ATP checkpoints require a Unix filesystem and TLS support",
    ));
    let mut report = match result {
        Ok(report) => report,
        Err(error) => CommandReport {
            value: json!({"ok": false, "error": error.value()}),
            failure: Some(error.message),
        },
    };
    report.value["schema"] = json!("asupersync.atp.checkpoint.v1");
    report.value["event"] = json!("atp_checkpoint");
    report.value["operation"] = json!(operation);
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &report.value)
        .map_err(|error| format!("write checkpoint result: {error}"))?;
    writeln!(output).map_err(|error| format!("write checkpoint result: {error}"))?;
    output
        .flush()
        .map_err(|error| format!("flush checkpoint result: {error}"))?;
    match report.failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(all(unix, feature = "tls"))]
mod supported {
    use super::{CheckpointCommand, CommandReport, ConnectionArgs, Failure, Value, json};
    use asupersync::Cx;
    use asupersync::net::atp::protocol::PeerId;
    use asupersync::net::atp::sdk::native::upload::recovery::{
        NativeCheckpointError, NativeCheckpointRetry, NativeCheckpointState,
        NativeCheckpointStatus, NativeUploadCheckpoint,
    };
    use asupersync::net::atp::sdk::native::{NativeTransferError, NativeUploadOptions};
    use asupersync::net::atp::sdk::{AtpSdk, NativeTransferClient, SessionConfig, TransferPolicy};
    use asupersync::net::atp::transport_quic::native_link::QuicClientTls;
    use asupersync::net::atp::transport_quic::{QuicConfig, SendReport};
    use asupersync::net::quic_native::handshake_driver::ATP_QUIC_ALPN;
    use std::fs::{File, OpenOptions};
    use std::future::Future;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::Path;
    use std::pin::Pin;
    use std::time::Duration;

    fn client(options: &ConnectionArgs) -> Result<NativeTransferClient, Failure> {
        if options.peer_id.trim().is_empty() || options.server_name.trim().is_empty() {
            return Err(Failure::new(
                "invalid_options",
                "peer-id and server-name must be nonempty",
            ));
        }
        let (roots, pinned_leafs) = match options.ca.as_deref() {
            Some(path) => {
                let roots = super::super::load_cert_chain(path)
                    .map_err(|error| Failure::new("tls_configuration", error))?;
                (roots.clone(), roots)
            }
            None => (
                super::super::load_native_root_certs()
                    .map_err(|error| Failure::new("tls_configuration", error))?,
                Vec::new(),
            ),
        };
        let server_name = super::super::quic_server_name(options.server_name.clone())
            .map_err(|error| Failure::new("tls_configuration", error))?;
        let tls = super::super::quic_cli_client_config(
            roots,
            pinned_leafs,
            vec![ATP_QUIC_ALPN.to_vec()],
        )
        .map_err(|error| Failure::new("tls_configuration", format!("{error:?}")))?;
        let timeout = Duration::from_secs(options.timeout_secs);
        let config = QuicConfig {
            // Checkpoints target the same receivers as `atp send --transport quic`.
            // Keep the library's established default geometry unchanged.
            symbol_size: super::super::resolved_symbol_size(None, true),
            max_transfer_bytes: options.max_bytes,
            idle_timeout: timeout,
            handshake_timeout: timeout,
            accept_timeout: timeout,
            client_tls: Some(QuicClientTls {
                server_name,
                config: tls,
            }),
            ..QuicConfig::default().use_transport_authenticated_symbols()
        };
        AtpSdk::new_in_process(SessionConfig {
            local_peer: PeerId::from_label(&options.peer_id),
            max_concurrent_transfers: 1,
            ..SessionConfig::default()
        })
        .with_transfer_policy(TransferPolicy {
            max_transfer_size_bytes: options.max_bytes,
            ..TransferPolicy::default()
        })
        .native_transfers(config)
        .map_err(|error| Failure::new("native_configuration", error.to_string()))
    }

    fn io_failure(error: std::io::Error) -> Failure {
        Failure::new("local_io", error.to_string())
    }

    fn require_reportable_directory(path: &Path) -> Result<(), Failure> {
        if std::fs::canonicalize(path)
            .map_err(io_failure)?
            .to_str()
            .is_none()
        {
            return Err(Failure::new(
                "invalid_directory",
                "checkpoint and spool directories must have UTF-8 canonical paths for JSON recovery reports",
            ));
        }
        Ok(())
    }

    // Open once, then check the actual descriptor. O_NONBLOCK prevents a FIFO
    // from parking the CLI before we can refuse its non-regular file type.
    fn source_file(source: &Path, spool: &Path) -> Result<File, Failure> {
        require_reportable_directory(spool)?;
        let parent = std::fs::symlink_metadata(spool).map_err(io_failure)?;
        if !parent.is_dir() || parent.permissions().mode() & 0o077 != 0 {
            return Err(Failure::new(
                "private_spool_required",
                "spool-dir must be an existing private directory (Unix mode 0700)",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(source)
            .map_err(io_failure)?;
        if !file.metadata().map_err(io_failure)?.is_file() {
            return Err(Failure::new(
                "regular_file_required",
                "source must be a regular file",
            ));
        }
        Ok(file)
    }

    fn checkpoint_value(checkpoint: &NativeUploadCheckpoint) -> Value {
        json!({
            "directory": checkpoint.directory,
            "remote": checkpoint.remote.to_string(),
            "file_name": checkpoint.file_name,
            "source_bytes": checkpoint.source_bytes,
            "source_sha256": hex::encode(checkpoint.source_sha256),
            "state": checkpoint.state,
            "attempt": checkpoint.attempt,
        })
    }

    fn receipt_value(report: &SendReport) -> Value {
        json!({
            "transfer_id": report.transfer_id,
            "bytes_sent": report.bytes_sent,
            "files": report.files,
            "symbols_sent": report.symbols_sent,
            "feedback_rounds": report.feedback_rounds,
            "merkle_root": report.merkle_root_hex,
            "receipt": report.receipt,
            "peer": report.peer.to_string(),
        })
    }

    fn status_value(status: &NativeCheckpointStatus) -> Value {
        json!({
            "ok": true,
            "checkpoint": checkpoint_value(&status.checkpoint),
            "cancelled": status.cancelled,
            "delivery_uncertain": status.delivery_uncertain(),
            "receipt": status.receipt.as_ref().map(receipt_value),
        })
    }

    fn failure(error: NativeCheckpointError) -> Failure {
        let (code, details) = match &error {
            NativeCheckpointError::Busy => ("busy", Value::Null),
            NativeCheckpointError::BindingMismatch => ("binding_mismatch", Value::Null),
            NativeCheckpointError::SourceChanged => ("source_changed", Value::Null),
            NativeCheckpointError::Uncertain { attempt } => (
                "uncertain_delivery",
                json!({"attempt": attempt, "delivery_uncertain": true}),
            ),
            NativeCheckpointError::StaleAttempt => ("stale_attempt", Value::Null),
            NativeCheckpointError::SnapshotMismatch => ("snapshot_mismatch", Value::Null),
            NativeCheckpointError::Cancelled {
                attempt,
                delivery_uncertain,
            } => (
                "cancelled",
                json!({"attempt": attempt, "delivery_uncertain": delivery_uncertain}),
            ),
            NativeCheckpointError::AttemptsExhausted => ("attempts_exhausted", Value::Null),
            NativeCheckpointError::ReceiptMismatch(report) => {
                ("receipt_mismatch", receipt_value(report))
            }
            NativeCheckpointError::Native(NativeTransferError::UncommittedSend(report)) => {
                ("uncommitted_send", receipt_value(report))
            }
            NativeCheckpointError::Publication { directory, .. } => {
                ("publication_failed", json!({"directory": directory}))
            }
            NativeCheckpointError::Invalid(_) => ("invalid_checkpoint", Value::Null),
            _ => ("checkpoint_failed", Value::Null),
        };
        Failure {
            code,
            message: error.to_string(),
            details,
        }
    }

    pub(super) fn execute(command: CheckpointCommand) -> Result<CommandReport, Failure> {
        let options = command.connection();
        let client = client(options)?;
        let workers = usize::from(options.workers);
        let source = match &command {
            CheckpointCommand::Prepare {
                source, spool_dir, ..
            } => Some(source_file(source, spool_dir)?),
            CheckpointCommand::Send { directory, .. }
            | CheckpointCommand::Status { directory, .. }
            | CheckpointCommand::Cancel { directory, .. } => {
                require_reportable_directory(directory)?;
                None
            }
        };
        let runtime = super::super::build_runtime(workers)
            .map_err(|error| Failure::new("runtime", error))?;
        let work: Pin<Box<dyn Future<Output = Result<CommandReport, Failure>> + Send>> =
            Box::pin(async move {
                let cx = Cx::current().expect("checkpoint runtime context");
                execute_owned(&cx, client, command, source).await
            });
        let outcome = runtime.block_on(runtime.handle().spawn(work));
        let drained = runtime.shutdown_timeout(Duration::from_secs(10));
        let mut report = match outcome {
            Ok(report) => report,
            Err(error) => CommandReport {
                value: json!({"ok": false, "error": error.value()}),
                failure: Some(error.message),
            },
        };
        if !drained {
            report.value["ok"] = json!(false);
            report.value["shutdown_error"] = json!("runtime did not drain within 10 seconds");
            report
                .failure
                .get_or_insert_with(|| "checkpoint runtime did not drain".to_string());
        }
        Ok(report)
    }

    async fn execute_owned(
        cx: &Cx,
        client: NativeTransferClient,
        command: CheckpointCommand,
        source: Option<File>,
    ) -> Result<CommandReport, Failure> {
        match command {
            CheckpointCommand::Prepare {
                source: path,
                spool_dir,
                name,
                connection,
            } => {
                let name = name
                    .or_else(|| path.file_name()?.to_str().map(str::to_owned))
                    .ok_or_else(|| {
                        Failure::new("invalid_filename", "source requires a portable --name")
                    })?;
                let mut options = NativeUploadOptions::new(spool_dir, name);
                options.max_bytes = Some(connection.max_bytes);
                options.source_idle_timeout = Duration::from_secs(connection.timeout_secs);
                let prepared = client
                    .prepare_reader(
                        cx,
                        connection.remote,
                        options,
                        asupersync::fs::File::from_std(source.expect("validated source file")),
                    )
                    .await
                    .map_err(failure)?;
                let cleanup = prepared.cleanup_error.as_ref().map(|error| {
                    json!({
                        "directory": error.directory,
                        "message": error.error.to_string(),
                    })
                });
                Ok(CommandReport {
                    value: json!({
                        "ok": cleanup.is_none(),
                        "checkpoint": checkpoint_value(&prepared.checkpoint),
                        "cancelled": false,
                        "delivery_uncertain": false,
                        "cleanup_error": cleanup,
                    }),
                    failure: prepared.cleanup_error.map(|error| {
                        format!(
                            "checkpoint prepared, but temporary spool cleanup failed: {}",
                            error.error
                        )
                    }),
                })
            }
            CheckpointCommand::Send {
                directory,
                acknowledge_uncertain_attempt,
                connection,
            } => {
                let retry = acknowledge_uncertain_attempt.map_or(
                    NativeCheckpointRetry::Never,
                    |attempt| NativeCheckpointRetry::AcknowledgeUncertain {
                        attempt: attempt.get(),
                    },
                );
                let attempt = client
                    .send_checkpoint(cx, &directory, connection.remote, retry)
                    .await
                    .map_err(failure)?;
                let (receipt, error) = match attempt.outcome {
                    Ok(report) => (Some(receipt_value(&report)), None),
                    Err(error) => (None, Some(failure(error))),
                };
                let persistence = attempt.persistence_error.as_ref().map(ToString::to_string);
                let failed = error
                    .as_ref()
                    .map(|error| error.message.clone())
                    .or_else(|| {
                        persistence.as_ref().map(|error| {
                            format!("peer receipt retained, but persisting it failed: {error}")
                        })
                    });
                Ok(CommandReport {
                    value: json!({
                        "ok": failed.is_none(),
                        "checkpoint": checkpoint_value(&attempt.checkpoint),
                        "cancelled": false,
                        "delivery_uncertain": attempt.checkpoint.state == NativeCheckpointState::Sending,
                        "cached_receipt": attempt.cached_receipt,
                        "receipt": receipt,
                        "error": error.as_ref().map(Failure::value),
                        "persistence_error": persistence,
                    }),
                    failure: failed,
                })
            }
            CheckpointCommand::Status {
                directory,
                connection,
            } => {
                let status = client
                    .inspect_checkpoint_status(cx, &directory, connection.remote)
                    .await
                    .map_err(failure)?;
                Ok(CommandReport {
                    value: status_value(&status),
                    failure: None,
                })
            }
            CheckpointCommand::Cancel {
                directory,
                connection,
            } => {
                let current = client
                    .inspect_checkpoint_status(cx, &directory, connection.remote)
                    .await
                    .map_err(failure)?;
                let status = client
                    .cancel_checkpoint(cx, &current.checkpoint)
                    .await
                    .map_err(failure)?;
                Ok(CommandReport {
                    value: status_value(&status),
                    failure: None,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn checkpoint_cli_requires_explicit_binding_and_exact_retry_attempt() {
        let parse = |tail: &[&str]| {
            let mut args = vec!["atp", "checkpoint"];
            args.extend_from_slice(tail);
            super::super::Cli::try_parse_from(args)
        };
        assert!(parse(&["send", "checkpoint"]).is_err());
        let common = [
            "--remote",
            "127.0.0.1:8472",
            "--server-name",
            "localhost",
            "--peer-id",
            "sender",
        ];
        for command in ["send", "status", "cancel"] {
            let mut args = vec![command, "checkpoint"];
            args.extend_from_slice(&common);
            let parsed = parse(&args).expect("explicit checkpoint binding");
            let super::super::Command::Checkpoint(parsed) = parsed.command else {
                panic!("checkpoint command")
            };
            if let CheckpointCommand::Send {
                acknowledge_uncertain_attempt,
                ..
            } = parsed.command
            {
                assert!(acknowledge_uncertain_attempt.is_none());
            }
        }
        let mut args = vec!["send", "checkpoint"];
        args.extend_from_slice(&common);
        args.extend_from_slice(&["--acknowledge-uncertain-attempt", "0"]);
        assert!(parse(&args).is_err(), "attempt zero cannot authorize retry");
        args.pop();
        args.push("2");
        let parsed = parse(&args).unwrap();
        let super::super::Command::Checkpoint(parsed) = parsed.command else {
            panic!("checkpoint command")
        };
        let CheckpointCommand::Send {
            acknowledge_uncertain_attempt,
            ..
        } = parsed.command
        else {
            panic!("send command")
        };
        assert_eq!(acknowledge_uncertain_attempt.unwrap().get(), 2);
        let mut invalid = vec!["status", "checkpoint"];
        invalid.extend_from_slice(&common);
        invalid.extend_from_slice(&["--workers", "0"]);
        assert!(parse(&invalid).is_err());
    }
}
