//! `atp` — a small, standalone, distributable ATP file-transfer tool.
//!
//! Unlike the full `asupersync` CLI, this binary exposes only the ATP transfer
//! surface and links a minimal feature set, so it is easy to `scp` to a host and
//! run. It moves actual file bytes, verified end to end, and fails closed. There
//! is no simulated progress.
//!
//! Three real transports are available, plus explicit sender-side fallback:
//! - `--transport tcp` (default): one reliable TCP stream
//!   (`asupersync::net::atp::transport_tcp`). Simple and robust.
//! - `--transport rq`: RaptorQ fountain symbols sprayed over multiple UDP
//!   sockets with a reliable TCP control plane
//!   (`asupersync::net::atp::transport_rq`). Built to saturate a lossy,
//!   high-latency path and tolerate packet loss without head-of-line blocking.
//! - `--transport quic`: ATP over QUIC/TLS-1.3 when built with `--features tls`.
//! - `--transport auto`: sender-side selection that tries QUIC, then RQ, then
//!   TCP, recording the selected transport and failed attempts in the JSON
//!   report.
//!
//! ```text
//! KEY=$(atp rq-keygen)
//! # on the receiver
//! atp recv ./inbox --listen 0.0.0.0:8472 --transport rq --rq-auth-key-hex "$KEY"
//! # on the sender
//! atp send ./my-folder receiver-host:8472 --transport rq --streams 8 --rq-auth-key-hex "$KEY"
//!
//! # rsync-like remote bootstrap over SSH; bulk bytes still use ATP
//! # and RQ symbol auth is generated/passed to the remote receiver.
//! atp send ./my-folder user@receiver:/srv/inbox --transport rq --prefer tailscale
//! ```

use std::env;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Child, Command as ProcessCommand, ExitCode, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_common::{FilterSet, TransferProgress, plan_transfer};
use asupersync::net::atp::transport_rq::{
    self, DEFAULT_MAX_BLOCK_SIZE, DEFAULT_MAX_FEEDBACK_ROUNDS, DEFAULT_REPAIR_OVERHEAD,
    DEFAULT_ROUND_TAIL_DRAIN_MS, DEFAULT_SYMBOL_SIZE, DEFAULT_UDP_FANOUT, RqConfig,
};
use asupersync::net::atp::transport_tcp::{
    self, DEFAULT_MAX_TRANSFER_BYTES, ReceiveReport, SendReport, TransferConfig, TransportError,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::{AUTH_KEY_SIZE, AuthKey, SecurityContext};
use clap::{Parser, Subcommand, ValueEnum};

const RQ_AUTH_ENV: &str = "ATP_RQ_AUTH_KEY_HEX";

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
    /// Generate a validator-accepted RQ symbol-auth key as lowercase hex.
    #[command(name = "rq-keygen")]
    RqKeygen,
}

/// Which real transport to use.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Transport {
    /// Sender-side fallback: try QUIC, then RQ, then TCP.
    Auto,
    /// One reliable TCP stream.
    Tcp,
    /// RaptorQ fountain symbols over multiple UDP sockets (+ TCP control).
    Rq,
    /// RaptorQ fountain symbols over a real QUIC/TLS-1.3 connection: symbols ride
    /// QUIC DATAGRAMs and the ATP control protocol rides one bidirectional
    /// stream, all under a single authenticated, encrypted UDP flow. Requires
    /// building `atp` with `--features tls`.
    Quic,
}

impl Transport {
    const fn cli_arg(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Tcp => "tcp",
            Self::Rq => "rq",
            Self::Quic => "quic",
        }
    }

    const fn auto_fallback_order() -> &'static [Self] {
        &[Self::Quic, Self::Rq, Self::Tcp]
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
    /// Sender bandwidth cap in bytes per second (quic/auto only).
    #[arg(long = "bwlimit", value_name = "BPS")]
    bwlimit_bps: Option<u64>,
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
    /// Maximum RaptorQ source-block size in bytes (rq/quic only).
    #[arg(long, default_value_t = DEFAULT_MAX_BLOCK_SIZE)]
    max_block_size: usize,
    /// Round-0 repair overhead factor, >= 1.0 (rq only).
    #[arg(long, default_value_t = DEFAULT_REPAIR_OVERHEAD)]
    repair_overhead: f64,
    /// Receiver quiet-drain window after each RQ round marker, in milliseconds.
    #[arg(long, default_value_t = DEFAULT_ROUND_TAIL_DRAIN_MS)]
    rq_tail_drain_ms: u64,
    /// Hex-encoded 32-byte RQ symbol-auth key, or set ATP_RQ_AUTH_KEY_HEX.
    ///
    /// Direct RQ transfers require this unless --rq-allow-unauthenticated-lab
    /// is explicitly set. SSH bootstrap auto-generates a per-transfer key when
    /// no key is supplied.
    #[arg(long, value_name = "HEX")]
    rq_auth_key_hex: Option<String>,
    /// Explicitly disable RQ/QUIC symbol authentication for loopback/lab-only
    /// runs. Applies to both `--transport rq` and `--transport quic`.
    #[arg(long)]
    rq_allow_unauthenticated_lab: bool,
    // ─── QUIC (`--transport quic`) TLS material ───
    /// PEM file of CA certificate(s) the sender trusts to verify the receiver's
    /// QUIC server certificate (quic only). Required unless the receiver's
    /// certificate chains to a system root; there is no insecure skip-verify.
    #[arg(long, value_name = "PATH")]
    ca: Option<PathBuf>,
    /// Server name to verify against the receiver's certificate SAN (quic only).
    /// Defaults to the target host.
    #[arg(long, value_name = "NAME")]
    server_name: Option<String>,
    /// Maximum QUIC handshake wait before sender fallback, in milliseconds
    /// (quic/auto only).
    #[arg(long, default_value_t = 30_000)]
    quic_handshake_timeout_ms: u64,
    /// For SSH bootstrap with `--transport quic`: path *on the remote host* to the
    /// PEM certificate chain the spawned receiver should present.
    #[arg(long, value_name = "REMOTE_PATH")]
    server_cert: Option<PathBuf>,
    /// For SSH bootstrap with `--transport quic`: path *on the remote host* to the
    /// PEM private key for the spawned receiver's certificate.
    #[arg(long, value_name = "REMOTE_PATH")]
    server_key: Option<PathBuf>,
    /// Compute and print the transfer plan (file list, sizes, total bytes, merkle
    /// root) as JSON without connecting or sending anything (rsync `--dry-run`).
    #[arg(long)]
    dry_run: bool,
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
    /// Maximum RaptorQ source-block size in bytes (rq/quic only; must match the sender).
    #[arg(long, default_value_t = DEFAULT_MAX_BLOCK_SIZE)]
    max_block_size: usize,
    /// Round-0 repair overhead factor (rq only).
    #[arg(long, default_value_t = DEFAULT_REPAIR_OVERHEAD)]
    repair_overhead: f64,
    /// Receiver quiet-drain window after each RQ round marker, in milliseconds.
    #[arg(long, default_value_t = DEFAULT_ROUND_TAIL_DRAIN_MS)]
    rq_tail_drain_ms: u64,
    /// Hex-encoded 32-byte RQ symbol-auth key, or set ATP_RQ_AUTH_KEY_HEX.
    #[arg(long, value_name = "HEX")]
    rq_auth_key_hex: Option<String>,
    /// Explicitly disable RQ symbol authentication for loopback/lab-only runs.
    #[arg(long)]
    rq_allow_unauthenticated_lab: bool,
    /// PEM certificate chain the QUIC receiver presents to senders (quic only).
    #[arg(long, value_name = "PATH")]
    server_cert: Option<PathBuf>,
    /// PEM private key for the QUIC receiver's certificate (quic only).
    #[arg(long, value_name = "PATH")]
    server_key: Option<PathBuf>,
    /// Maximum QUIC handshake wait, in milliseconds (quic only).
    #[arg(long, default_value_t = 30_000)]
    quic_handshake_timeout_ms: u64,
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
    max_block_size: usize,
    repair_overhead: f64,
    tail_drain_ms: u64,
    rq_auth_key_hex: Option<&str>,
    rq_allow_unauthenticated_lab: bool,
) -> Result<RqConfig, String> {
    let max_block_size = normalize_max_block_size(symbol_size, max_block_size)?;
    let config = RqConfig {
        symbol_size,
        udp_fanout: streams.max(1),
        max_block_size,
        repair_overhead: repair_overhead.max(1.0),
        max_transfer_bytes: max_bytes,
        max_feedback_rounds: DEFAULT_MAX_FEEDBACK_ROUNDS,
        round_tail_drain: Duration::from_millis(tail_drain_ms),
        ..RqConfig::default()
    };
    let auth = resolve_rq_auth_choice(rq_auth_key_hex, rq_allow_unauthenticated_lab, false)?;
    config_with_rq_auth(config, &auth)
}

fn normalize_max_block_size(symbol_size: u16, max_block_size: usize) -> Result<usize, String> {
    if max_block_size == 0 {
        return Err("--max-block-size must be greater than 0".to_string());
    }
    Ok(max_block_size.max(usize::from(symbol_size.max(1))))
}

fn normalize_bwlimit_bps(bwlimit_bps: Option<u64>) -> Result<Option<u64>, String> {
    match bwlimit_bps {
        Some(0) => Err("--bwlimit must be greater than 0".to_string()),
        Some(cap) => Ok(Some(cap)),
        None => Ok(None),
    }
}

fn validate_requested_bwlimit_transport(
    requested: Transport,
    bwlimit_bps: Option<u64>,
) -> Result<(), String> {
    let bwlimit_bps = normalize_bwlimit_bps(bwlimit_bps)?;
    if bwlimit_bps.is_some() && matches!(requested, Transport::Tcp | Transport::Rq) {
        return Err(format!(
            "--bwlimit is currently wired only for --transport quic or auto; \
             --transport {} would ignore the cap",
            requested.cli_arg()
        ));
    }
    Ok(())
}

// ─── QUIC (`--transport quic`) TLS material + config ─────────────────────────

/// Load a PEM certificate chain (one or more certificates) from `path`.
#[cfg(feature = "tls")]
fn load_cert_chain(
    path: &std::path::Path,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("read cert {}: {e}", path.display()))?;
    let mut reader = std::io::BufReader::new(pem.as_slice());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certs in {}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", path.display()));
    }
    Ok(certs)
}

/// Load a single PEM private key from `path`.
#[cfg(feature = "tls")]
fn load_private_key(
    path: &std::path::Path,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("read key {}: {e}", path.display()))?;
    let mut reader = std::io::BufReader::new(pem.as_slice());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("parse key in {}: {e}", path.display()))?
        .ok_or_else(|| format!("no private key found in {}", path.display()))
}

/// Best-effort default SNI: the host portion of a `host:port` target.
fn default_server_name(target: &str) -> String {
    let target = target.trim();
    let host = if let Some(after_open) = target.strip_prefix('[') {
        match after_open.split_once(']') {
            Some((host, "")) => host,
            Some((host, after_close))
                if after_close.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
                }) =>
            {
                host
            }
            None => target,
            _ => target,
        }
    } else {
        match target.rsplit_once(':') {
            Some((host, port))
                if target.matches(':').count() == 1
                    && !port.is_empty()
                    && port.bytes().all(|b| b.is_ascii_digit()) =>
            {
                host
            }
            _ => target,
        }
    };
    host.to_string()
}

fn default_quic_server_name_for_ssh(remote: &RemoteTarget) -> String {
    default_server_name(ssh_host_without_user(&remote.ssh_host))
}

/// Apply the shared RQ/QUIC per-symbol auth posture to a base QUIC config.
#[cfg(feature = "tls")]
fn quic_with_symbol_auth(
    base: asupersync::net::atp::transport_quic::QuicConfig,
    rq_auth_key_hex: Option<&str>,
    rq_allow_unauthenticated_lab: bool,
) -> Result<asupersync::net::atp::transport_quic::QuicConfig, String> {
    match resolve_rq_auth_choice(rq_auth_key_hex, rq_allow_unauthenticated_lab, false)? {
        RqAuthChoice::KeyHex(key_hex) => {
            let key = auth_key_from_hex(&key_hex)?;
            Ok(base.with_symbol_auth(SecurityContext::new(key)))
        }
        RqAuthChoice::UnauthenticatedLab => Ok(base.allow_unauthenticated_for_trusted_transport()),
    }
}

/// Build the sending QUIC config: client TLS trust + per-symbol auth + tuning.
#[cfg(feature = "tls")]
fn quic_config_send(
    args: &SendArgs,
) -> Result<asupersync::net::atp::transport_quic::QuicConfig, String> {
    use asupersync::net::atp::transport_quic::{QuicConfig, native_link::QuicClientTls};
    use asupersync::net::quic_native::handshake_driver::{ATP_QUIC_ALPN, client_config};
    use rustls::pki_types::ServerName;

    let roots = match args.ca.as_deref() {
        Some(path) => load_cert_chain(path)?,
        None => Vec::new(),
    };
    let name = args
        .server_name
        .clone()
        .unwrap_or_else(|| default_server_name(&args.target));
    let server_name = ServerName::try_from(name.clone())
        .map_err(|e| format!("invalid --server-name {name:?}: {e}"))?;
    let config = client_config(roots, vec![ATP_QUIC_ALPN.to_vec()])
        .map_err(|e| format!("build QUIC client TLS config: {e:?}"))?;

    let base = QuicConfig {
        symbol_size: args.symbol_size,
        max_block_size: normalize_max_block_size(args.symbol_size, args.max_block_size)?,
        repair_overhead: args.repair_overhead.max(1.0),
        max_transfer_bytes: args.max_bytes,
        bwlimit_bps: normalize_bwlimit_bps(args.bwlimit_bps)?,
        handshake_timeout: Duration::from_millis(args.quic_handshake_timeout_ms),
        ..QuicConfig::default()
    };
    let mut cfg = quic_with_symbol_auth(
        base,
        args.rq_auth_key_hex.as_deref(),
        args.rq_allow_unauthenticated_lab,
    )?;
    cfg.client_tls = Some(QuicClientTls {
        server_name,
        config,
    });
    Ok(cfg)
}

/// Build the receiving QUIC config: server cert/key + per-symbol auth + tuning.
#[cfg(feature = "tls")]
fn quic_config_recv(
    args: &RecvArgs,
) -> Result<asupersync::net::atp::transport_quic::QuicConfig, String> {
    use asupersync::net::atp::transport_quic::{QuicConfig, native_link::QuicServerTls};
    use asupersync::net::quic_native::handshake_driver::{ATP_QUIC_ALPN, server_config};

    let cert_path = args.server_cert.as_deref().ok_or_else(|| {
        "atp recv --transport quic requires --server-cert <PEM chain>".to_string()
    })?;
    let key_path = args
        .server_key
        .as_deref()
        .ok_or_else(|| "atp recv --transport quic requires --server-key <PEM key>".to_string())?;
    let cert_chain = load_cert_chain(cert_path)?;
    let key = load_private_key(key_path)?;
    let config = server_config(cert_chain, key, vec![ATP_QUIC_ALPN.to_vec()])
        .map_err(|e| format!("build QUIC server TLS config: {e:?}"))?;

    let base = QuicConfig {
        symbol_size: args.symbol_size,
        max_block_size: normalize_max_block_size(args.symbol_size, args.max_block_size)?,
        repair_overhead: args.repair_overhead.max(1.0),
        max_transfer_bytes: args.max_bytes,
        handshake_timeout: Duration::from_millis(args.quic_handshake_timeout_ms),
        ..QuicConfig::default()
    };
    let mut cfg = quic_with_symbol_auth(
        base,
        args.rq_auth_key_hex.as_deref(),
        args.rq_allow_unauthenticated_lab,
    )?;
    cfg.server_tls = Some(QuicServerTls { config });
    Ok(cfg)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RqAuthChoice {
    KeyHex(String),
    UnauthenticatedLab,
}

fn resolve_rq_auth_choice(
    explicit_key_hex: Option<&str>,
    allow_unauthenticated_lab: bool,
    generate_if_missing: bool,
) -> Result<RqAuthChoice, String> {
    let configured_key = explicit_key_hex
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var(RQ_AUTH_ENV)
                .ok()
                .map(|key| key.trim().to_string())
                .filter(|key| !key.is_empty())
        });

    if allow_unauthenticated_lab {
        if configured_key.is_some() {
            return Err(format!(
                "--rq-allow-unauthenticated-lab conflicts with --rq-auth-key-hex/{RQ_AUTH_ENV}"
            ));
        }
        return Ok(RqAuthChoice::UnauthenticatedLab);
    }

    if let Some(key_hex) = configured_key {
        return normalize_rq_auth_key_hex(&key_hex).map(RqAuthChoice::KeyHex);
    }

    if generate_if_missing {
        return generate_rq_auth_key_hex().map(RqAuthChoice::KeyHex);
    }

    Err(format!(
        "RQ transport requires symbol authentication: pass --rq-auth-key-hex <64-hex>, \
         set {RQ_AUTH_ENV}, use SSH bootstrap so atp can generate a per-transfer key, \
         or explicitly pass --rq-allow-unauthenticated-lab for loopback/lab only"
    ))
}

fn config_with_rq_auth(config: RqConfig, auth: &RqAuthChoice) -> Result<RqConfig, String> {
    match auth {
        RqAuthChoice::KeyHex(key_hex) => {
            let key = auth_key_from_hex(key_hex)?;
            Ok(config.with_symbol_auth(SecurityContext::new(key)))
        }
        RqAuthChoice::UnauthenticatedLab => {
            Ok(config.allow_unauthenticated_for_trusted_transport())
        }
    }
}

fn normalize_rq_auth_key_hex(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let key_hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let _ = auth_key_from_hex(key_hex)?;
    Ok(key_hex.to_ascii_lowercase())
}

fn auth_key_from_hex(key_hex: &str) -> Result<AuthKey, String> {
    if key_hex.len() != AUTH_KEY_SIZE * 2 {
        return Err(format!(
            "RQ auth key must be exactly {} hex characters for a {AUTH_KEY_SIZE}-byte key",
            AUTH_KEY_SIZE * 2
        ));
    }
    if !key_hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("RQ auth key must contain only hexadecimal characters".to_string());
    }

    let mut bytes = [0u8; AUTH_KEY_SIZE];
    hex::decode_to_slice(key_hex, &mut bytes)
        .map_err(|err| format!("decode RQ auth key hex: {err}"))?;
    AuthKey::from_bytes(bytes).map_err(|err| format!("RQ auth key rejected: {err}"))
}

fn generate_rq_auth_key_hex() -> Result<String, String> {
    for _ in 0..128 {
        let mut bytes = [0u8; AUTH_KEY_SIZE];
        getrandom::fill(&mut bytes).map_err(|err| format!("generate RQ auth key: {err}"))?;
        if AuthKey::from_bytes(bytes).is_ok() {
            return Ok(hex::encode(bytes));
        }
    }
    Err("generated 128 candidate RQ auth keys, but all failed entropy validation".to_string())
}

fn build_runtime(workers: usize) -> Result<asupersync::runtime::Runtime, String> {
    // The RQ transport needs a real platform reactor for efficient UDP I/O; the
    // TCP transport benefits from it too. Enable it for both.
    // A blocking pool is required for CPU-bound fan-out (parallel RaptorQ per-block encode/decode,
    // F3/F6.3): without it `Cx::spawn_blocking` silently runs inline on a worker, capping parallelism
    // at `worker_threads`. Size it from the host parallelism so the encode/decode can use the cores.
    let max_blocking = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(8)
        .clamp(workers.max(2), 64);
    RuntimeBuilder::multi_thread()
        .worker_threads(workers.max(1))
        .enable_platform_reactor(true)
        .blocking_threads(workers.max(2), max_blocking)
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
    validate_requested_bwlimit_transport(args.transport, args.bwlimit_bps)?;
    // `--dry-run` computes the transfer plan from the source and prints it
    // without resolving the target or opening any socket (rsync `--dry-run`).
    if args.dry_run {
        return run_send_dry_run(&args);
    }
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

/// Print the transfer plan (file list, sizes, total bytes, merkle root) the
/// transport *would* send, computed via a bounded-memory streaming hash pass
/// with no network I/O. Transport-agnostic: the plan is identical for `tcp`/`rq`.
fn run_send_dry_run(args: &SendArgs) -> Result<(), String> {
    let runtime = build_runtime(args.workers)?;
    let source = args.source.clone();
    // Use the exact config a real TCP send would (`tcp_config`) so the printed
    // plan matches what the transfer commits: same chunk size, metadata policy
    // (symlink/dir/special-file handling), and hardlink dedup.
    let cfg = tcp_config(args.max_bytes);
    let plan = runtime
        .block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("dry-run cx");
            plan_transfer(
                &cx,
                &source,
                cfg.chunk_size,
                &cfg.metadata_policy,
                cfg.preserve_hardlinks,
            )
            .await
        }))
        .map_err(|e| e.to_string())?;
    print_json(&plan);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransportAttempt {
    transport: Transport,
    status: TransportAttemptStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TransportAttemptStatus {
    Failed(String),
    Selected,
}

impl TransportAttemptStatus {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Failed(_) => "failed",
            Self::Selected => "selected",
        }
    }
}

fn transport_attempts_json(attempts: &[TransportAttempt]) -> Vec<serde_json::Value> {
    attempts
        .iter()
        .map(|attempt| match &attempt.status {
            TransportAttemptStatus::Failed(error) => serde_json::json!({
                "transport": attempt.transport.cli_arg(),
                "status": attempt.status.as_str(),
                "error": error,
            }),
            TransportAttemptStatus::Selected => serde_json::json!({
                "transport": attempt.transport.cli_arg(),
                "status": attempt.status.as_str(),
            }),
        })
        .collect()
}

fn add_auto_selection_metadata(
    mut report: serde_json::Value,
    attempts: &[TransportAttempt],
) -> serde_json::Value {
    if let Some(object) = report.as_object_mut() {
        let selected_transport = object
            .get("transport")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(null));
        object.insert(
            "requested_transport".to_string(),
            serde_json::json!(Transport::Auto.cli_arg()),
        );
        object.insert("selected_transport".to_string(), selected_transport);
        object.insert(
            "transport_attempts".to_string(),
            serde_json::json!(transport_attempts_json(attempts)),
        );
    }
    report
}

fn auto_transport_exhausted_error(attempts: &[TransportAttempt]) -> String {
    let details = attempts
        .iter()
        .filter_map(|attempt| match &attempt.status {
            TransportAttemptStatus::Failed(error) => {
                Some(format!("{}: {error}", attempt.transport.cli_arg()))
            }
            TransportAttemptStatus::Selected => None,
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!("atp --transport auto exhausted fallback order (quic -> rq -> tcp): {details}")
}

fn run_send_to_addr(args: SendArgs, addr: SocketAddr) -> Result<(), String> {
    let runtime = build_runtime(args.workers)?;
    let report = if args.transport == Transport::Auto {
        run_send_auto_to_addr(&runtime, &args, addr)?
    } else {
        send_to_addr_with_transport(&runtime, &args, args.transport, addr)?
    };
    print_json(&report);
    Ok(())
}

fn run_send_auto_to_addr(
    runtime: &asupersync::runtime::Runtime,
    args: &SendArgs,
    addr: SocketAddr,
) -> Result<serde_json::Value, String> {
    let mut attempts = Vec::new();
    for transport in Transport::auto_fallback_order().iter().copied() {
        eprintln!("[atp] transport selection: trying {}", transport.cli_arg());
        match send_to_addr_with_transport(runtime, args, transport, addr) {
            Ok(report) => {
                eprintln!(
                    "[atp] transport selection: selected {}",
                    transport.cli_arg()
                );
                attempts.push(TransportAttempt {
                    transport,
                    status: TransportAttemptStatus::Selected,
                });
                return Ok(add_auto_selection_metadata(report, &attempts));
            }
            Err(error) => {
                eprintln!(
                    "[atp] transport selection: {} unavailable: {error}",
                    transport.cli_arg()
                );
                attempts.push(TransportAttempt {
                    transport,
                    status: TransportAttemptStatus::Failed(error),
                });
            }
        }
    }
    Err(auto_transport_exhausted_error(&attempts))
}

fn send_to_addr_with_transport(
    runtime: &asupersync::runtime::Runtime,
    args: &SendArgs,
    transport: Transport,
    addr: SocketAddr,
) -> Result<serde_json::Value, String> {
    let bwlimit_bps = normalize_bwlimit_bps(args.bwlimit_bps)?;
    if bwlimit_bps.is_some() && transport != Transport::Quic {
        return Err(format!(
            "--bwlimit is currently wired only for quic; {} fallback skipped \
             to avoid ignoring the cap",
            transport.cli_arg()
        ));
    }

    let source = args.source.clone();
    let peer_id = args.peer_id.clone();
    match transport {
        Transport::Auto => {
            Err("internal error: auto is a selector, not a concrete transport".to_string())
        }
        Transport::Tcp => {
            let cfg = tcp_config(args.max_bytes);
            // Monotonic progress + ETA on stderr (stdout stays the JSON report).
            let start = std::time::Instant::now();
            let report: SendReport = runtime
                .block_on(runtime.handle().spawn(async move {
                    let cx = Cx::current().expect("sender cx");
                    let filter = FilterSet::new();
                    transport_tcp::send_path_filtered(
                        &cx,
                        addr,
                        &source,
                        cfg,
                        &peer_id,
                        &filter,
                        move |done, total| {
                            let mut progress = TransferProgress::new(total, 0);
                            progress.record_bytes(done);
                            let snap = progress.snapshot(start.elapsed());
                            let eta = snap
                                .eta
                                .map_or_else(String::new, |e| format!("  eta {e:.1?}"));
                            eprintln!(
                                "[atp] {:>3.0}%  {done} / {total} bytes  {:.0} B/s{eta}",
                                snap.fraction * 100.0,
                                snap.rate_bytes_per_sec,
                            );
                        },
                    )
                    .await
                }))
                .map_err(|e: TransportError| e.to_string())?;
            Ok(tcp_send_json(&report))
        }
        Transport::Rq => {
            let cfg = rq_config(
                args.max_bytes,
                args.symbol_size,
                args.streams,
                args.max_block_size,
                args.repair_overhead,
                args.rq_tail_drain_ms,
                args.rq_auth_key_hex.as_deref(),
                args.rq_allow_unauthenticated_lab,
            )?;
            let report = runtime
                .block_on(runtime.handle().spawn(async move {
                    let cx = Cx::current().expect("sender cx");
                    transport_rq::send_path(&cx, addr, &source, cfg, &peer_id).await
                }))
                .map_err(|e| e.to_string())?;
            Ok(rq_send_json(&report))
        }
        Transport::Quic => {
            #[cfg(feature = "tls")]
            {
                let cfg = quic_config_send(args)?;
                let report = runtime
                    .block_on(runtime.handle().spawn(async move {
                        let cx = Cx::current().expect("sender cx");
                        asupersync::net::atp::transport_quic::send_path(
                            &cx, addr, &source, cfg, &peer_id,
                        )
                        .await
                    }))
                    .map_err(
                        |e: asupersync::net::atp::transport_quic::QuicTransportError| e.to_string(),
                    )?;
                Ok(quic_send_json(&report))
            }
            #[cfg(not(feature = "tls"))]
            {
                Err("atp --transport quic requires building atp with --features tls".to_string())
            }
        }
    }
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

fn run_send_via_ssh(mut args: SendArgs, remote: &RemoteTarget) -> Result<(), String> {
    if args.no_tailscale && args.prefer == PathPreference::Tailscale {
        return Err("--no-tailscale conflicts with --prefer tailscale".to_string());
    }
    if args.transport == Transport::Auto {
        return Err(
            "SSH bootstrap with --transport auto is not wired yet; choose tcp, rq, or quic"
                .to_string(),
        );
    }
    validate_requested_bwlimit_transport(args.transport, args.bwlimit_bps)?;

    // Both the RQ and QUIC transports carry per-symbol HMAC auth; SSH bootstrap
    // generates a fresh per-transfer key when none was supplied and feeds it to
    // both ends. (TCP has no symbol auth.)
    let rq_auth = if args.transport != Transport::Tcp {
        let auth = resolve_rq_auth_choice(
            args.rq_auth_key_hex.as_deref(),
            args.rq_allow_unauthenticated_lab,
            true,
        )?;
        if let RqAuthChoice::KeyHex(key_hex) = &auth {
            args.rq_auth_key_hex = Some(key_hex.clone());
        }
        Some(auth)
    } else {
        None
    };
    if args.transport == Transport::Quic
        && (args.server_cert.is_none() || args.server_key.is_none())
    {
        return Err(
            "SSH bootstrap with --transport quic requires --server-cert and \
                    --server-key (paths on the remote host to the receiver's PEM \
                    certificate chain and private key)"
                .to_string(),
        );
    }

    let data_host = choose_data_host(&args, remote);
    if args.transport == Transport::Quic && args.server_name.is_none() {
        args.server_name = Some(default_quic_server_name_for_ssh(remote));
    }
    let data_target = socket_target(&data_host, args.remote_listen.port());
    let addr = resolve(&data_target)?;
    let mut child = spawn_remote_receiver(&args, remote, rq_auth.as_ref())?;
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

fn spawn_remote_receiver(
    args: &SendArgs,
    remote: &RemoteTarget,
    rq_auth: Option<&RqAuthChoice>,
) -> Result<Child, String> {
    let receiver_peer_id = format!("{}-remote", args.peer_id);
    let mut argv = vec![
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
        "--max-block-size".to_string(),
        args.max_block_size.to_string(),
        "--repair-overhead".to_string(),
        args.repair_overhead.to_string(),
        "--rq-tail-drain-ms".to_string(),
        args.rq_tail_drain_ms.to_string(),
    ];
    if matches!(rq_auth, Some(RqAuthChoice::UnauthenticatedLab)) {
        argv.push("--rq-allow-unauthenticated-lab".to_string());
    }
    if args.transport == Transport::Quic {
        // Validated in `run_send_via_ssh`; these are paths on the remote host.
        if let Some(cert) = &args.server_cert {
            argv.push("--server-cert".to_string());
            argv.push(cert.display().to_string());
        }
        if let Some(key) = &args.server_key {
            argv.push("--server-key".to_string());
            argv.push(key.display().to_string());
        }
    }

    let remote_command = match rq_auth {
        Some(RqAuthChoice::KeyHex(key_hex)) => {
            shell_command_with_env(&[(RQ_AUTH_ENV, key_hex.as_str())], &argv)
        }
        _ => shell_command(&argv),
    };
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

fn shell_command_with_env(env_vars: &[(&str, &str)], argv: &[String]) -> String {
    let mut parts = env_vars
        .iter()
        .map(|(name, value)| format!("{name}={}", shell_quote(value)))
        .collect::<Vec<_>>();
    parts.push(shell_command(argv));
    parts.join(" ")
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
    if args.transport == Transport::Auto {
        return Err(
            "atp recv/serve --transport auto is sender-only; choose tcp, rq, or quic".to_string(),
        );
    }
    let runtime = build_runtime(args.workers)?;
    let dest = args.dest.clone();
    let listen = args.listen;
    let peer_id = args.peer_id.clone();
    let one_shot = args.once && !persistent;
    let udp_bind_ip = listen.ip().to_string();

    match args.transport {
        Transport::Auto => Err(
            "atp recv/serve --transport auto is sender-only; choose tcp, rq, or quic".to_string(),
        ),
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
                args.max_block_size,
                args.repair_overhead,
                args.rq_tail_drain_ms,
                args.rq_auth_key_hex.as_deref(),
                args.rq_allow_unauthenticated_lab,
            )?;
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
        Transport::Quic => {
            #[cfg(feature = "tls")]
            {
                let cfg = quic_config_recv(&args)?;
                runtime.block_on(runtime.handle().spawn(async move {
                    use asupersync::net::atp::transport_quic::native_link::{
                        bind_server_endpoint, receive_on_endpoint,
                    };
                    let cx = Cx::current().expect("receiver cx");
                    asupersync::fs::create_dir_all(&dest)
                        .await
                        .map_err(|e| format!("create dest {}: {e}", dest.display()))?;
                    if one_shot {
                        let endpoint = bind_server_endpoint(&cx, listen)
                            .await
                            .map_err(|e| e.to_string())?;
                        eprintln!(
                            "atp: quic listening on {}, dest {}",
                            endpoint.local_addr(),
                            dest.display()
                        );
                        let report = receive_on_endpoint(&cx, endpoint, &dest, &cfg, &peer_id)
                            .await
                            .map_err(|e| e.to_string())?;
                        print_json(&quic_recv_json(&report));
                        Ok::<(), String>(())
                    } else {
                        eprintln!("atp: quic listening on {listen}, dest {}", dest.display());
                        // Each accepted transfer consumes the endpoint; rebind the
                        // same address for the next one. `--listen` must use a fixed
                        // port for persistent serving (port 0 would drift).
                        loop {
                            let endpoint = bind_server_endpoint(&cx, listen)
                                .await
                                .map_err(|e| e.to_string())?;
                            match receive_on_endpoint(&cx, endpoint, &dest, &cfg, &peer_id).await {
                                Ok(r) => print_json(&quic_recv_json(&r)),
                                Err(e) => eprintln!("atp: transfer failed: {e}"),
                            }
                        }
                    }
                }))
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = (&dest, &listen, &peer_id, one_shot, &udp_bind_ip);
                Err("atp --transport quic requires building atp with --features tls".to_string())
            }
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
        "symbols_accepted": report.symbols_accepted,
        "feedback_rounds": report.feedback_rounds,
        "decode_count": report.decode_count,
        "decode_micros": report.decode_micros,
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
        "symbols_sent": report.symbols_sent,
        "feedback_rounds": report.feedback_rounds,
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

#[cfg(feature = "tls")]
fn quic_recv_json(
    report: &asupersync::net::atp::transport_quic::ReceiveReport,
) -> serde_json::Value {
    serde_json::json!({
        "event": "atp_receive", "transport": "quic",
        "transfer_id": report.transfer_id,
        "committed": report.committed,
        "bytes_received": report.bytes_received,
        "files": report.files,
        "symbols_accepted": report.symbols_accepted,
        "feedback_rounds": report.feedback_rounds,
        "decode_count": report.decode_count,
        "decode_micros": report.decode_micros,
        "committed_paths": report.committed_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "peer": report.peer.to_string(),
    })
}

#[cfg(feature = "tls")]
fn quic_send_json(report: &asupersync::net::atp::transport_quic::SendReport) -> serde_json::Value {
    serde_json::json!({
        "event": "atp_send", "transport": "quic",
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

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn rq_auth_key_hex_accepts_valid_32_byte_key_and_normalizes_case() {
        let upper = VALID_KEY_HEX.to_ascii_uppercase();

        assert_eq!(
            normalize_rq_auth_key_hex(&upper),
            Ok(VALID_KEY_HEX.to_string())
        );
        assert!(auth_key_from_hex(VALID_KEY_HEX).is_ok());
    }

    #[test]
    fn rq_auth_key_hex_rejects_wrong_length_non_hex_and_weak_keys() {
        assert!(normalize_rq_auth_key_hex("abcd").is_err());
        assert!(normalize_rq_auth_key_hex(&"g".repeat(AUTH_KEY_SIZE * 2)).is_err());
        assert!(normalize_rq_auth_key_hex(&"00".repeat(AUTH_KEY_SIZE)).is_err());
    }

    #[test]
    fn direct_rq_requires_auth_or_explicit_lab_override() {
        let missing = match rq_config(1024, 1024, 1, 512 * 1024, 1.0, 2, None, false) {
            Ok(_) => panic!("direct rq without auth must fail closed"),
            Err(err) => err,
        };
        assert!(missing.contains("requires symbol authentication"));

        assert!(
            rq_config(
                1024,
                1024,
                1,
                512 * 1024,
                1.0,
                2,
                Some(VALID_KEY_HEX),
                false
            )
            .is_ok()
        );
        assert!(rq_config(1024, 1024, 1, 512 * 1024, 1.0, 2, None, true).is_ok());
    }

    #[test]
    fn rq_config_applies_max_block_size_for_e4_sweeps() {
        let config = rq_config(
            10 * 1024 * 1024,
            1024,
            4,
            512 * 1024,
            1.0,
            2,
            Some(VALID_KEY_HEX),
            false,
        )
        .expect("authenticated rq config should build");

        assert_eq!(config.max_block_size, 512 * 1024);
        assert_eq!(config.max_block_size / usize::from(config.symbol_size), 512);
    }

    #[test]
    fn max_block_size_rejects_zero_and_floors_to_symbol_size() {
        assert_eq!(
            normalize_max_block_size(1024, 0),
            Err("--max-block-size must be greater than 0".to_string())
        );
        assert_eq!(normalize_max_block_size(1024, 512), Ok(1024));
        assert_eq!(normalize_max_block_size(1024, 512 * 1024), Ok(512 * 1024));
    }

    #[test]
    fn bwlimit_rejects_zero_and_non_quic_concrete_transports() {
        assert_eq!(normalize_bwlimit_bps(None), Ok(None));
        assert_eq!(
            normalize_bwlimit_bps(Some(256 * 1024)),
            Ok(Some(256 * 1024))
        );
        assert_eq!(
            normalize_bwlimit_bps(Some(0)),
            Err("--bwlimit must be greater than 0".to_string())
        );

        assert!(validate_requested_bwlimit_transport(Transport::Quic, Some(1)).is_ok());
        assert!(validate_requested_bwlimit_transport(Transport::Auto, Some(1)).is_ok());
        assert!(
            validate_requested_bwlimit_transport(Transport::Tcp, Some(1))
                .expect_err("tcp must not silently ignore bwlimit")
                .contains("would ignore the cap")
        );
        assert!(
            validate_requested_bwlimit_transport(Transport::Rq, Some(1))
                .expect_err("rq must not silently ignore bwlimit")
                .contains("would ignore the cap")
        );
    }

    #[test]
    fn send_parser_accepts_rsync_style_bwlimit_flag() {
        let cli = Cli::parse_from([
            "atp",
            "send",
            "./src",
            "receiver.example:8472",
            "--transport",
            "quic",
            "--bwlimit",
            "262144",
        ]);

        let Command::Send(args) = cli.command else {
            panic!("expected send command");
        };
        assert_eq!(args.transport, Transport::Quic);
        assert_eq!(args.bwlimit_bps, Some(262_144));
    }

    #[test]
    fn lab_override_conflicts_with_configured_key() {
        let err = resolve_rq_auth_choice(Some(VALID_KEY_HEX), true, false)
            .expect_err("explicit unauthenticated lab mode must not accept a key too");
        assert!(err.contains("conflicts"));
    }

    #[test]
    fn ssh_bootstrap_can_generate_transfer_local_auth_key() {
        match resolve_rq_auth_choice(None, false, true) {
            Ok(RqAuthChoice::KeyHex(key_hex)) => {
                assert_eq!(key_hex.len(), AUTH_KEY_SIZE * 2);
                assert!(auth_key_from_hex(&key_hex).is_ok());
            }
            other => panic!("expected generated key, got {other:?}"),
        }
    }

    #[test]
    fn remote_env_shell_command_quotes_key_outside_argv() {
        let argv = vec![
            "atp".to_string(),
            "recv".to_string(),
            "/srv/in box".to_string(),
        ];
        let command = shell_command_with_env(&[(RQ_AUTH_ENV, VALID_KEY_HEX)], &argv);

        assert!(command.starts_with("ATP_RQ_AUTH_KEY_HEX='000102"));
        assert!(command.contains("'atp' 'recv' '/srv/in box'"));
        assert!(!command.contains("--rq-auth-key-hex"));
    }

    #[test]
    fn default_server_name_extracts_host_without_port() {
        assert_eq!(
            default_server_name("receiver.example:8472"),
            "receiver.example"
        );
        assert_eq!(default_server_name("[2001:db8::1]:8472"), "2001:db8::1");
        assert_eq!(default_server_name("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(default_server_name("2001:db8::1"), "2001:db8::1");
        assert_eq!(default_server_name("receiver.example"), "receiver.example");
    }

    #[test]
    fn ssh_quic_default_server_name_uses_ssh_host_not_remote_path() {
        let remote = RemoteTarget::parse("user@receiver.example:/srv/inbox").unwrap();
        assert_eq!(
            default_quic_server_name_for_ssh(&remote),
            "receiver.example"
        );

        let remote_v6 = RemoteTarget::parse("user@[2001:db8::10]:/srv/inbox").unwrap();
        assert_eq!(default_quic_server_name_for_ssh(&remote_v6), "2001:db8::10");
    }

    #[test]
    fn auto_transport_order_prefers_quic_then_rq_then_tcp() {
        assert_eq!(
            Transport::auto_fallback_order(),
            &[Transport::Quic, Transport::Rq, Transport::Tcp]
        );
        assert_eq!(Transport::Auto.cli_arg(), "auto");
    }

    #[test]
    fn auto_selection_metadata_preserves_concrete_transport_and_attempts() {
        let report = serde_json::json!({
            "event": "atp_send",
            "transport": "tcp",
            "committed": true,
        });
        let attempts = vec![
            TransportAttempt {
                transport: Transport::Quic,
                status: TransportAttemptStatus::Failed("tls unavailable".to_string()),
            },
            TransportAttempt {
                transport: Transport::Rq,
                status: TransportAttemptStatus::Failed("auth missing".to_string()),
            },
            TransportAttempt {
                transport: Transport::Tcp,
                status: TransportAttemptStatus::Selected,
            },
        ];

        let annotated = add_auto_selection_metadata(report, &attempts);

        assert_eq!(annotated["transport"], "tcp");
        assert_eq!(annotated["requested_transport"], "auto");
        assert_eq!(annotated["selected_transport"], "tcp");
        assert_eq!(annotated["transport_attempts"][0]["transport"], "quic");
        assert_eq!(annotated["transport_attempts"][0]["status"], "failed");
        assert_eq!(
            annotated["transport_attempts"][0]["error"],
            "tls unavailable"
        );
        assert_eq!(annotated["transport_attempts"][2]["transport"], "tcp");
        assert_eq!(annotated["transport_attempts"][2]["status"], "selected");
        assert!(annotated["transport_attempts"][2]["error"].is_null());
    }

    #[test]
    fn auto_transport_exhausted_error_lists_failed_fallbacks() {
        let attempts = vec![
            TransportAttempt {
                transport: Transport::Quic,
                status: TransportAttemptStatus::Failed("quic refused".to_string()),
            },
            TransportAttempt {
                transport: Transport::Rq,
                status: TransportAttemptStatus::Failed("rq refused".to_string()),
            },
            TransportAttempt {
                transport: Transport::Tcp,
                status: TransportAttemptStatus::Failed("tcp refused".to_string()),
            },
        ];

        let error = auto_transport_exhausted_error(&attempts);

        assert!(error.contains("quic -> rq -> tcp"));
        assert!(error.contains("quic: quic refused"));
        assert!(error.contains("rq: rq refused"));
        assert!(error.contains("tcp: tcp refused"));
    }
}

/// Raise the soft open-file-descriptor limit to the hard limit at startup.
///
/// The RaptorQ receiver opens one staging file per manifest entry and keeps it
/// open while the transfer is in flight, so a directory transfer with thousands
/// of files would otherwise exceed the default soft limit (commonly 1024) and
/// fail with EMFILE ("Too many open files") — see bead
/// `asupersync-atp-dataplane-redesign-317hxr.26` (E-14). Raising the soft limit
/// to the hard limit is the standard stopgap; the complete fix is a bounded FD
/// pool in the receiver. Best-effort: any error is ignored.
#[allow(unsafe_code)]
fn raise_fd_limit() {
    // SAFETY: `getrlimit`/`setrlimit` are invoked with the valid `RLIMIT_NOFILE`
    // resource identifier and a fully-initialized, non-aliased `rlimit` value
    // that lives for the duration of each call; the kernel only reads/writes
    // through the supplied pointer, and both return codes are checked before the
    // struct is used or written back.
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) == 0 && lim.rlim_cur < lim.rlim_max {
            lim.rlim_cur = lim.rlim_max;
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lim);
        }
    }
}

fn main() -> ExitCode {
    raise_fd_limit();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Send(args) => run_send(args),
        Command::Recv(args) => run_recv(args, false),
        Command::Serve(args) => run_recv(args, true),
        Command::RqKeygen => generate_rq_auth_key_hex().map(|key| {
            println!("{key}");
        }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("atp failed: {err}");
            ExitCode::FAILURE
        }
    }
}
