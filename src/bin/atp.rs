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
//!
//! # rsync-like remote bootstrap over SSH; bulk bytes still use ATP
//! atp send ./my-folder user@receiver:/srv/inbox --transport rq --prefer tailscale
//! ```

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Child, Command as ProcessCommand, ExitCode, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_rq::{
    self, DEFAULT_MAX_FEEDBACK_ROUNDS, DEFAULT_REPAIR_OVERHEAD, DEFAULT_ROUND_TAIL_DRAIN_MS,
    DEFAULT_SYMBOL_SIZE, DEFAULT_UDP_FANOUT, RqConfig,
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

impl Transport {
    const fn cli_arg(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Rq => "rq",
        }
    }
}

/// Preferred network path when SSH is used only as a bootstrap channel.
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum PathPreference {
    /// Use explicit data host, Tailscale if requested by config later, else SSH host.
    Auto,
    /// Use the SSH host/public address for ATP data.
    Direct,
    /// Try a Tailscale address reported by the remote host, then fall back.
    Tailscale,
}

#[derive(Parser)]
struct SendArgs {
    /// Source file or directory to send.
    source: PathBuf,
    /// Destination as host:port, or rsync-like SSH target `user@host:/path`.
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
    /// Preferred path for SSH-bootstrapped transfers.
    #[arg(long, value_enum, default_value_t = PathPreference::Auto)]
    prefer: PathPreference,
    /// Disable Tailscale probing even when `--prefer tailscale` is present.
    #[arg(long)]
    no_tailscale: bool,
    /// Override the host/IP used for ATP data after SSH bootstrap.
    #[arg(long)]
    data_host: Option<String>,
    /// Remote listen address for the SSH-started receiver.
    #[arg(long, default_value = "0.0.0.0:8472")]
    remote_listen: SocketAddr,
    /// Remote `atp` binary path or command name used by SSH bootstrap.
    #[arg(long, default_value = "atp")]
    remote_atp: String,
    /// Extra raw OpenSSH option; repeat for multiple argv words.
    #[arg(long = "ssh-option")]
    ssh_options: Vec<String>,
    /// Seconds to wait for the remote receiver to bind and print readiness.
    #[arg(long, default_value_t = 15)]
    ssh_ready_timeout_secs: u64,
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
    /// Receiver quiet-drain window after each RQ round marker, in milliseconds.
    #[arg(long, default_value_t = DEFAULT_ROUND_TAIL_DRAIN_MS)]
    rq_tail_drain_ms: u64,
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
    /// Receiver quiet-drain window after each RQ round marker, in milliseconds.
    #[arg(long, default_value_t = DEFAULT_ROUND_TAIL_DRAIN_MS)]
    rq_tail_drain_ms: u64,
}

fn tcp_config(max_bytes: u64) -> TransferConfig {
    TransferConfig {
        max_transfer_bytes: max_bytes,
        ..TransferConfig::default()
    }
}

fn rq_config(
    max_bytes: u64,
    symbol_size: u16,
    streams: usize,
    repair_overhead: f64,
    tail_drain_ms: u64,
) -> RqConfig {
    RqConfig {
        symbol_size,
        udp_fanout: streams.max(1),
        repair_overhead: repair_overhead.max(1.0),
        max_transfer_bytes: max_bytes,
        max_feedback_rounds: DEFAULT_MAX_FEEDBACK_ROUNDS,
        round_tail_drain: Duration::from_millis(tail_drain_ms),
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
    match resolve(&args.target) {
        Ok(addr) => run_send_to_addr(args, addr),
        Err(resolve_error) => {
            if let Some(remote) = RemoteTarget::parse(&args.target) {
                run_send_via_ssh(args, &remote)
            } else {
                Err(resolve_error)
            }
        }
    }
}

fn run_send_to_addr(args: SendArgs, addr: SocketAddr) -> Result<(), String> {
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
                args.rq_tail_drain_ms,
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

#[derive(Debug)]
struct RemoteTarget {
    ssh_host: String,
    remote_path: String,
}

impl RemoteTarget {
    fn parse(target: &str) -> Option<Self> {
        let (ssh_host, remote_path) = split_remote_target(target)?;
        if ssh_host.trim().is_empty() || remote_path.trim().is_empty() {
            return None;
        }
        let looks_like_remote_path = target.contains('@')
            || remote_path.starts_with('/')
            || remote_path.starts_with("./")
            || remote_path.starts_with("../")
            || remote_path.starts_with('~');
        if !looks_like_remote_path {
            return None;
        }
        Some(Self {
            ssh_host: ssh_host.to_string(),
            remote_path: remote_path.to_string(),
        })
    }
}

fn split_remote_target(target: &str) -> Option<(&str, &str)> {
    if let Some(open) = target.rfind('[') {
        let bracketed_host = open == 0 || target.as_bytes().get(open - 1) == Some(&b'@');
        if bracketed_host {
            let close = open + 1 + target[open + 1..].find(']')?;
            if target.as_bytes().get(close + 1) == Some(&b':') {
                return Some((&target[..=close], &target[close + 2..]));
            }
        }
    }
    target.split_once(':')
}

fn run_send_via_ssh(args: SendArgs, remote: &RemoteTarget) -> Result<(), String> {
    if args.no_tailscale && args.prefer == PathPreference::Tailscale {
        return Err("--no-tailscale conflicts with --prefer tailscale".to_string());
    }

    let data_host = choose_data_host(&args, remote);
    let data_target = socket_target(&data_host, args.remote_listen.port());
    let addr = resolve(&data_target)?;
    let mut child = spawn_remote_receiver(&args, remote)?;
    let stderr_log = wait_for_remote_ready(
        &mut child,
        Duration::from_secs(args.ssh_ready_timeout_secs.max(1)),
    )?;

    let send_result = run_send_to_addr(args, addr);
    if send_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return send_result;
    }

    let status = wait_child_timeout(&mut child, Duration::from_secs(60))?;
    if !status.success() {
        let log = stderr_log
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| "<stderr unavailable>".to_string());
        return Err(format!(
            "remote atp receiver exited with {status}; stderr: {}",
            last_log_lines(&log, 8)
        ));
    }

    Ok(())
}

fn choose_data_host(args: &SendArgs, remote: &RemoteTarget) -> String {
    if let Some(host) = &args.data_host {
        return host.clone();
    }
    if args.no_tailscale || args.prefer != PathPreference::Tailscale {
        return ssh_host_without_user(&remote.ssh_host).to_string();
    }
    probe_remote_tailscale_ipv4(args, &remote.ssh_host)
        .unwrap_or_else(|| ssh_host_without_user(&remote.ssh_host).to_string())
}

fn probe_remote_tailscale_ipv4(args: &SendArgs, ssh_host: &str) -> Option<String> {
    let mut command = ssh_command(args, ssh_host);
    command.arg("command -v tailscale >/dev/null 2>&1 && tailscale ip -4 | sed -n '1p'");
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let candidate = stdout.lines().next()?.trim();
    if candidate.is_empty() || candidate.parse::<std::net::IpAddr>().is_err() {
        return None;
    }
    Some(candidate.to_string())
}

fn spawn_remote_receiver(args: &SendArgs, remote: &RemoteTarget) -> Result<Child, String> {
    let receiver_peer_id = format!("{}-remote", args.peer_id);
    let argv = vec![
        args.remote_atp.clone(),
        "recv".to_string(),
        remote.remote_path.clone(),
        "--listen".to_string(),
        args.remote_listen.to_string(),
        "--once".to_string(),
        "--transport".to_string(),
        args.transport.cli_arg().to_string(),
        "--peer-id".to_string(),
        receiver_peer_id,
        "--max-bytes".to_string(),
        args.max_bytes.to_string(),
        "--workers".to_string(),
        args.workers.max(1).to_string(),
        "--symbol-size".to_string(),
        args.symbol_size.to_string(),
        "--repair-overhead".to_string(),
        args.repair_overhead.to_string(),
        "--rq-tail-drain-ms".to_string(),
        args.rq_tail_drain_ms.to_string(),
    ];
    let remote_command = shell_command(&argv);
    let mut command = ssh_command(args, &remote.ssh_host);
    command
        .arg(remote_command)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
        .spawn()
        .map_err(|err| format!("spawn ssh receiver {}: {err}", remote.ssh_host))
}

fn ssh_command(args: &SendArgs, ssh_host: &str) -> ProcessCommand {
    let mut command = ProcessCommand::new("ssh");
    command
        .arg("-T")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg("ConnectTimeout=15");
    for option in &args.ssh_options {
        command.arg(option);
    }
    command.arg(ssh_host);
    command
}

fn wait_for_remote_ready(
    child: &mut Child,
    timeout: Duration,
) -> Result<Arc<Mutex<String>>, String> {
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "ssh stderr pipe unavailable".to_string())?;
    let stderr_log = Arc::new(Mutex::new(String::new()));
    let log_for_thread = Arc::clone(&stderr_log);
    let (ready_tx, ready_rx) = mpsc::channel::<bool>();

    thread::spawn(move || {
        let mut ready_sent = false;
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap_or_else(|err| format!("<stderr read error: {err}>"));
            if let Ok(mut log) = log_for_thread.lock() {
                log.push_str(&line);
                log.push('\n');
            }
            if !ready_sent && line.contains("listening on") {
                ready_sent = true;
                let _ = ready_tx.send(true);
            }
        }
        if !ready_sent {
            let _ = ready_tx.send(false);
        }
    });

    match ready_rx.recv_timeout(timeout) {
        Ok(true) => Ok(stderr_log),
        Ok(false) => {
            let log = stderr_log
                .lock()
                .map(|s| s.clone())
                .unwrap_or_else(|_| "<stderr unavailable>".to_string());
            Err(format!(
                "remote atp receiver exited before readiness; stderr: {}",
                last_log_lines(&log, 8)
            ))
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(format!(
                "remote atp receiver did not report readiness within {}s",
                timeout.as_secs()
            ))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("remote atp readiness watcher disconnected".to_string())
        }
    }
}

fn wait_child_timeout(child: &mut Child, timeout: Duration) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|err| err.to_string())? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "remote atp receiver did not exit within {}s after send completion",
                timeout.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn shell_command(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    let mut out = String::from("'");
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn ssh_host_without_user(ssh_host: &str) -> &str {
    ssh_host.rsplit_once('@').map_or(ssh_host, |(_, host)| host)
}

fn socket_target(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn last_log_lines(log: &str, count: usize) -> String {
    let lines: Vec<&str> = log.lines().collect();
    lines
        .iter()
        .skip(lines.len().saturating_sub(count))
        .copied()
        .collect::<Vec<_>>()
        .join("\n")
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
            let cfg = rq_config(
                args.max_bytes,
                args.symbol_size,
                1,
                args.repair_overhead,
                args.rq_tail_drain_ms,
            );
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
