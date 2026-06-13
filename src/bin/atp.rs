//! `atp` — a small, standalone, distributable ATP file-transfer tool.
//!
//! Unlike the full `asupersync` CLI, this binary exposes only the ATP transfer
//! surface and links a minimal feature set, so it is easy to `scp` to a host and
//! run. It moves actual file bytes, verified end to end, and fails closed. There
//! is no simulated progress.
//!
//! Two real transports are available:
//! - `--transport tcp` (default): one reliable TCP stream
//!   (`asupersync::net::atp::transport_tcp`). Simple and robust.
//! - `--transport rq`: RaptorQ fountain symbols sprayed over multiple UDP
//!   sockets with a reliable TCP control plane
//!   (`asupersync::net::atp::transport_rq`). Built to saturate a lossy,
//!   high-latency path and tolerate packet loss without head-of-line blocking.
//!
//! ```text
//! # on the receiver
//! atp recv ./inbox --listen 0.0.0.0:8472
//! # on the sender
//! atp send ./my-folder receiver-host:8472 --transport rq --streams 8
//! ```

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_rq::{
    self, DEFAULT_MAX_FEEDBACK_ROUNDS, DEFAULT_REPAIR_OVERHEAD, DEFAULT_SYMBOL_SIZE,
    DEFAULT_UDP_FANOUT, RqConfig,
};
use asupersync::net::atp::transport_tcp::{
    self, DEFAULT_MAX_TRANSFER_BYTES, ReceiveReport, SendReport, TransferConfig, TransportError,
};
use asupersync::runtime::RuntimeBuilder;
use clap::{Parser, Subcommand, ValueEnum};

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

/// Which real transport to use.
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Transport {
    /// One reliable TCP stream.
    Tcp,
    /// RaptorQ fountain symbols over multiple UDP sockets (+ TCP control).
    Rq,
}

#[derive(Parser)]
struct SendArgs {
    /// Source file or directory to send.
    source: PathBuf,
    /// Destination peer as host:port (e.g. `203.0.113.7:8472`).
    target: String,
    /// Transport to use.
    #[arg(long, value_enum, default_value_t = Transport::Tcp)]
    transport: Transport,
    /// This peer's advertised identity label.
    #[arg(long, default_value = "atp-sender")]
    peer_id: String,
    /// Maximum transfer size in bytes.
    #[arg(long, default_value_t = DEFAULT_MAX_TRANSFER_BYTES)]
    max_bytes: u64,
    /// Worker threads for the local runtime.
    #[arg(long, default_value_t = 4)]
    workers: usize,
    // ─── RaptorQ (`--transport rq`) tuning ───
    /// RaptorQ symbol size in bytes (rq only).
    #[arg(long, default_value_t = DEFAULT_SYMBOL_SIZE)]
    symbol_size: u16,
    /// Number of UDP sockets to spray across (rq only).
    #[arg(long, default_value_t = DEFAULT_UDP_FANOUT)]
    streams: usize,
    /// Round-0 repair overhead factor, >= 1.0 (rq only).
    #[arg(long, default_value_t = DEFAULT_REPAIR_OVERHEAD)]
    repair_overhead: f64,
}

#[derive(Parser)]
struct RecvArgs {
    /// Destination directory for received transfers.
    dest: PathBuf,
    /// Address to listen on (TCP control + the RQ UDP socket binds on this IP).
    #[arg(long, default_value = "0.0.0.0:8472")]
    listen: SocketAddr,
    /// Transport to accept.
    #[arg(long, value_enum, default_value_t = Transport::Tcp)]
    transport: Transport,
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
    #[arg(long, default_value_t = 4)]
    workers: usize,
    /// RaptorQ symbol size in bytes (rq only; must match the sender).
    #[arg(long, default_value_t = DEFAULT_SYMBOL_SIZE)]
    symbol_size: u16,
    /// Round-0 repair overhead factor (rq only).
    #[arg(long, default_value_t = DEFAULT_REPAIR_OVERHEAD)]
    repair_overhead: f64,
}

fn tcp_config(max_bytes: u64) -> TransferConfig {
    TransferConfig {
        max_transfer_bytes: max_bytes,
        ..TransferConfig::default()
    }
}

fn rq_config(max_bytes: u64, symbol_size: u16, streams: usize, repair_overhead: f64) -> RqConfig {
    RqConfig {
        symbol_size,
        udp_fanout: streams.max(1),
        repair_overhead: repair_overhead.max(1.0),
        max_transfer_bytes: max_bytes,
        max_feedback_rounds: DEFAULT_MAX_FEEDBACK_ROUNDS,
        ..RqConfig::default()
    }
}

fn build_runtime(workers: usize) -> Result<asupersync::runtime::Runtime, String> {
    // The RQ transport needs a real platform reactor for efficient UDP I/O; the
    // TCP transport benefits from it too. Enable it for both.
    RuntimeBuilder::multi_thread()
        .worker_threads(workers.max(1))
        .enable_platform_reactor(true)
        .build()
        .map_err(|e| format!("build runtime: {e}"))
}

fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(json) => println!("{json}"),
        Err(err) => eprintln!("{{\"error\":\"json: {err}\"}}"),
    }
}

fn resolve(target: &str) -> Result<SocketAddr, String> {
    target
        .to_socket_addrs()
        .map_err(|e| format!("resolve {target}: {e}"))?
        .next()
        .ok_or_else(|| format!("{target} resolved to no addresses"))
}

fn run_send(args: SendArgs) -> Result<(), String> {
    let addr = resolve(&args.target)?;
    let runtime = build_runtime(args.workers)?;
    let source = args.source.clone();
    let peer_id = args.peer_id.clone();
    match args.transport {
        Transport::Tcp => {
            let cfg = tcp_config(args.max_bytes);
            let report: SendReport = runtime
                .block_on(runtime.handle().spawn(async move {
                    let cx = Cx::current().expect("sender cx");
                    transport_tcp::send_path(&cx, addr, &source, cfg, &peer_id).await
                }))
                .map_err(|e: TransportError| e.to_string())?;
            print_json(&tcp_send_json(&report));
        }
        Transport::Rq => {
            let cfg = rq_config(
                args.max_bytes,
                args.symbol_size,
                args.streams,
                args.repair_overhead,
            );
            let report = runtime
                .block_on(runtime.handle().spawn(async move {
                    let cx = Cx::current().expect("sender cx");
                    transport_rq::send_path(&cx, addr, &source, cfg, &peer_id).await
                }))
                .map_err(|e| e.to_string())?;
            print_json(&rq_send_json(&report));
        }
    }
    Ok(())
}

fn run_recv(args: RecvArgs, persistent: bool) -> Result<(), String> {
    let runtime = build_runtime(args.workers)?;
    let dest = args.dest.clone();
    let listen = args.listen;
    let peer_id = args.peer_id.clone();
    let one_shot = args.once && !persistent;
    let udp_bind_ip = listen.ip().to_string();

    match args.transport {
        Transport::Tcp => {
            let cfg = tcp_config(args.max_bytes);
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("receiver cx");
                asupersync::fs::create_dir_all(&dest)
                    .await
                    .map_err(|e| format!("create dest {}: {e}", dest.display()))?;
                let listener = TcpListener::bind(listen)
                    .await
                    .map_err(|e| format!("bind {listen}: {e}"))?;
                let bound = listener.local_addr().map_err(|e| e.to_string())?;
                eprintln!("atp: tcp listening on {bound}, dest {}", dest.display());
                if one_shot {
                    let report: ReceiveReport =
                        transport_tcp::receive_once(&cx, &listener, &dest, cfg, &peer_id)
                            .await
                            .map_err(|e| e.to_string())?;
                    print_json(&tcp_recv_json(&report));
                    Ok::<(), String>(())
                } else {
                    transport_tcp::serve(&cx, listener, dest.clone(), cfg, peer_id.clone(), |o| {
                        match o {
                            Ok(r) => print_json(&tcp_recv_json(&r)),
                            Err(e) => eprintln!("atp: transfer failed: {e}"),
                        }
                    })
                    .await
                    .map_err(|e| e.to_string())
                }
            }))
        }
        Transport::Rq => {
            let cfg = rq_config(args.max_bytes, args.symbol_size, 1, args.repair_overhead);
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("receiver cx");
                asupersync::fs::create_dir_all(&dest)
                    .await
                    .map_err(|e| format!("create dest {}: {e}", dest.display()))?;
                let listener = TcpListener::bind(listen)
                    .await
                    .map_err(|e| format!("bind {listen}: {e}"))?;
                let bound = listener.local_addr().map_err(|e| e.to_string())?;
                eprintln!(
                    "atp: rq control listening on {bound} (udp on {udp_bind_ip}), dest {}",
                    dest.display()
                );
                if one_shot {
                    let report = transport_rq::receive_once(
                        &cx,
                        &listener,
                        &udp_bind_ip,
                        &dest,
                        cfg,
                        &peer_id,
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                    print_json(&rq_recv_json(&report));
                    Ok::<(), String>(())
                } else {
                    transport_rq::serve(
                        &cx,
                        listener,
                        udp_bind_ip.clone(),
                        dest.clone(),
                        cfg,
                        peer_id.clone(),
                        |o| match o {
                            Ok(r) => print_json(&rq_recv_json(&r)),
                            Err(e) => eprintln!("atp: transfer failed: {e}"),
                        },
                    )
                    .await
                    .map_err(|e| e.to_string())
                }
            }))
        }
    }
}

fn tcp_recv_json(report: &ReceiveReport) -> serde_json::Value {
    serde_json::json!({
        "event": "atp_receive", "transport": "tcp",
        "transfer_id": report.transfer_id,
        "committed": report.committed,
        "bytes_received": report.bytes_received,
        "files": report.files,
        "committed_paths": report.committed_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "peer": report.peer.to_string(),
    })
}

fn tcp_send_json(report: &SendReport) -> serde_json::Value {
    serde_json::json!({
        "event": "atp_send", "transport": "tcp",
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

fn rq_recv_json(report: &transport_rq::ReceiveReport) -> serde_json::Value {
    serde_json::json!({
        "event": "atp_receive", "transport": "rq",
        "transfer_id": report.transfer_id,
        "committed": report.committed,
        "bytes_received": report.bytes_received,
        "files": report.files,
        "symbols_accepted": report.symbols_accepted,
        "feedback_rounds": report.feedback_rounds,
        "committed_paths": report.committed_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "peer": report.peer.to_string(),
    })
}

fn rq_send_json(report: &transport_rq::SendReport) -> serde_json::Value {
    serde_json::json!({
        "event": "atp_send", "transport": "rq",
        "transfer_id": report.transfer_id,
        "committed": report.receipt.committed,
        "bytes_sent": report.bytes_sent,
        "files": report.files,
        "symbols_sent": report.symbols_sent,
        "feedback_rounds": report.feedback_rounds,
        "merkle_root": report.merkle_root_hex,
        "sha_ok": report.receipt.sha_ok,
        "merkle_ok": report.receipt.merkle_ok,
        "peer": report.peer.to_string(),
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Send(args) => run_send(args),
        Command::Recv(args) => run_recv(args, false),
        Command::Serve(args) => run_recv(args, true),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("atp failed: {err}");
            ExitCode::FAILURE
        }
    }
}
