//! `atp` — a small, standalone, distributable ATP file-transfer tool.
//!
//! Unlike the full `asupersync` CLI, this binary exposes only the ATP transfer
//! surface and links a minimal feature set, so it is easy to `scp` to a host and
//! run. It uses the real ATP-over-TCP transport
//! (`asupersync::net::atp::transport_tcp`) — it moves actual file bytes,
//! verified end to end, and fails closed. There is no simulated progress.
//!
//! ```text
//! # on the receiver
//! atp recv ./inbox --listen 0.0.0.0:8472
//! # on the sender
//! atp send ./my-folder receiver-host:8472
//! ```

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_tcp::{
    DEFAULT_MAX_TRANSFER_BYTES, ReceiveReport, SendReport, TransferConfig, TransportError,
    receive_once, send_path, serve,
};
use asupersync::runtime::RuntimeBuilder;
use clap::{Parser, Subcommand};

/// Standalone ATP transfer tool.
#[derive(Parser)]
#[command(name = "atp", version, about = "Standalone ATP file-transfer tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Send a file or directory to a listening peer.
    Send(SendArgs),
    /// Receive transfers into a destination directory.
    Recv(RecvArgs),
    /// Alias for `recv` that listens persistently (daemon-style).
    Serve(RecvArgs),
}

#[derive(Parser)]
struct SendArgs {
    /// Source file or directory to send.
    source: PathBuf,
    /// Destination peer as host:port (e.g. `203.0.113.7:8472`).
    target: String,
    /// This peer's advertised identity label.
    #[arg(long, default_value = "atp-sender")]
    peer_id: String,
    /// Maximum transfer size in bytes.
    #[arg(long, default_value_t = DEFAULT_MAX_TRANSFER_BYTES)]
    max_bytes: u64,
    /// Worker threads for the local runtime.
    #[arg(long, default_value_t = 2)]
    workers: usize,
}

#[derive(Parser)]
struct RecvArgs {
    /// Destination directory for received transfers.
    dest: PathBuf,
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:8472")]
    listen: SocketAddr,
    /// Receive exactly one transfer, then exit (handy for scripted tests).
    #[arg(long)]
    once: bool,
    /// This peer's advertised identity label.
    #[arg(long, default_value = "atp-receiver")]
    peer_id: String,
    /// Maximum transfer size in bytes.
    #[arg(long, default_value_t = DEFAULT_MAX_TRANSFER_BYTES)]
    max_bytes: u64,
    /// Worker threads for the local runtime.
    #[arg(long, default_value_t = 2)]
    workers: usize,
}

fn config(max_bytes: u64) -> TransferConfig {
    TransferConfig {
        max_transfer_bytes: max_bytes,
        ..TransferConfig::default()
    }
}

fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(json) => println!("{json}"),
        Err(err) => eprintln!("{{\"error\":\"json: {err}\"}}"),
    }
}

fn run_send(args: SendArgs) -> Result<SendReport, String> {
    let addr = args
        .target
        .to_socket_addrs()
        .map_err(|e| format!("resolve {}: {e}", args.target))?
        .next()
        .ok_or_else(|| format!("{} resolved to no addresses", args.target))?;
    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(args.workers.max(1))
        .build()
        .map_err(|e| format!("build runtime: {e}"))?;
    let cfg = config(args.max_bytes);
    let source = args.source.clone();
    let peer_id = args.peer_id.clone();
    runtime
        .block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("sender cx");
            send_path(&cx, addr, &source, cfg, &peer_id).await
        }))
        .map_err(|e: TransportError| e.to_string())
}

fn run_recv(args: RecvArgs, persistent: bool) -> Result<(), String> {
    let runtime = RuntimeBuilder::multi_thread()
        .worker_threads(args.workers.max(1))
        .build()
        .map_err(|e| format!("build runtime: {e}"))?;
    let cfg = config(args.max_bytes);
    let dest = args.dest.clone();
    let listen = args.listen;
    let peer_id = args.peer_id.clone();
    let one_shot = args.once && !persistent;

    let result: Result<(), String> = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("receiver cx");
        asupersync::fs::create_dir_all(&dest)
            .await
            .map_err(|e| format!("create dest {}: {e}", dest.display()))?;
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|e| format!("bind {listen}: {e}"))?;
        let bound = listener.local_addr().map_err(|e| e.to_string())?;
        eprintln!("atp: listening on {bound}, dest {}", dest.display());

        if one_shot {
            let report: ReceiveReport = receive_once(&cx, &listener, &dest, cfg, &peer_id)
                .await
                .map_err(|e| e.to_string())?;
            print_json(&report_json(&report));
            Ok(())
        } else {
            serve(
                &cx,
                listener,
                dest.clone(),
                cfg,
                peer_id.clone(),
                |outcome| match outcome {
                    Ok(report) => print_json(&report_json(&report)),
                    Err(err) => eprintln!("atp: transfer failed: {err}"),
                },
            )
            .await
            .map_err(|e| e.to_string())
        }
    }));
    result
}

fn report_json(report: &ReceiveReport) -> serde_json::Value {
    serde_json::json!({
        "event": "atp_receive",
        "transfer_id": report.transfer_id,
        "committed": report.committed,
        "bytes_received": report.bytes_received,
        "files": report.files,
        "committed_paths": report.committed_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "peer": report.peer.to_string(),
    })
}

fn send_report_json(report: &SendReport) -> serde_json::Value {
    serde_json::json!({
        "event": "atp_send",
        "transfer_id": report.transfer_id,
        "committed": report.receipt.committed,
        "bytes_sent": report.bytes_sent,
        "files": report.files,
        "merkle_root": report.merkle_root_hex,
        "sha_ok": report.receipt.sha_ok,
        "merkle_ok": report.receipt.merkle_ok,
        "peer": report.peer.to_string(),
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Send(args) => match run_send(args) {
            Ok(report) => {
                print_json(&send_report_json(&report));
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("atp send failed: {err}");
                ExitCode::FAILURE
            }
        },
        Command::Recv(args) => match run_recv(args, false) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("atp recv failed: {err}");
                ExitCode::FAILURE
            }
        },
        Command::Serve(args) => match run_recv(args, true) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("atp serve failed: {err}");
                ExitCode::FAILURE
            }
        },
    }
}
