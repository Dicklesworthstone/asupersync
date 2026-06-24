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

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, ExitCode, ExitStatus, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asupersync::atp::delta::{
    CasChunkRef, ContentAddressedChunkStore as DeltaChunkStore, DeltaResyncMode, DeltaResyncPlan,
    DeltaResyncSendItem, PersistentChunkManifest, ReceiverCasCoverage, ReceiverSubchunkSignature,
    build_delta_resync_send_plan, decode_subdelta_ops,
    plan_incremental_resync_with_receiver_coverage,
};
use asupersync::atp::delta_subchunk::{self, SubBlockSignature};
use asupersync::atp::object::ContentId;
use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::transport_common::{FilterSet, TransferProgress, plan_transfer};
use asupersync::net::atp::transport_rq::{
    self, DEFAULT_MAX_FEEDBACK_ROUNDS, DEFAULT_REPAIR_OVERHEAD, DEFAULT_ROUND_TAIL_DRAIN_MS,
    DEFAULT_SYMBOL_SIZE, DEFAULT_UDP_FANOUT, RqConfig,
};
use asupersync::net::atp::transport_tcp::{
    self, DEFAULT_MAX_TRANSFER_BYTES, ReceiveReport, SendReport, TransferConfig, TransportError,
};
use asupersync::runtime::RuntimeBuilder;
use asupersync::security::{AUTH_KEY_SIZE, AuthKey, SecurityContext};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand, ValueEnum};
use sha2::{Digest, Sha256};

const RQ_AUTH_ENV: &str = "ATP_RQ_AUTH_KEY_HEX";
const DELTA_STATE_DIR: &str = ".asupersync-atp-delta-v1";
const DELTA_STATE_FILE: &str = "state.json";
const DELTA_CHUNK_DIR: &str = "chunks";
const DELTA_SUBCHUNK_DIR: &str = "subchunks";
const DELTA_PACKAGE_PREFIX: &str = ".asupersync-atp-delta-package-";
const DELTA_PACKAGE_FILE: &str = "delta-package.json";
const DELTA_STATE_SCHEMA: &str = "asupersync.atp.cli-delta-state.v1";
const DELTA_SUBCHUNK_SIGNATURE_REQUEST_SCHEMA: &str =
    "asupersync.atp.cli-delta-subchunk-signature-request.v1";
const DELTA_SUBCHUNK_SIGNATURE_RESPONSE_SCHEMA: &str =
    "asupersync.atp.cli-delta-subchunk-signature-response.v1";
const DELTA_PACKAGE_SCHEMA: &str = "asupersync.atp.cli-delta-package.v1";
const DELTA_TREE_OBJECT_MAGIC: &[u8] = b"ASUP_ATP_CLI_DELTA_TREE_OBJECT_V2\0";
const DELTA_TREE_OBJECT_CDC_WINDOW_BYTES: usize = 64;
const DELTA_TREE_OBJECT_MIN_CHUNK_BYTES: usize = 16 * 1024;
const DELTA_TREE_OBJECT_AVG_CHUNK_BYTES: usize = 32 * 1024;
const DELTA_TREE_OBJECT_MAX_CHUNK_BYTES: usize = 64 * 1024;
const DELTA_TREE_OBJECT_BOUNDARY_MASK: u64 = (DELTA_TREE_OBJECT_AVG_CHUNK_BYTES as u64) - 1;
const AUTO_MAX_BLOCK_SIZE: usize = 512 * 1024;

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

    const fn auto_fallback_order(delta_enabled: bool) -> &'static [Self] {
        if delta_enabled {
            &[Self::Tcp]
        } else {
            &[Self::Quic, Self::Rq, Self::Tcp]
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
    /// Maximum RaptorQ source-block size in bytes, `auto`, or `0` (rq/quic only).
    #[arg(
        long,
        default_value_t = MaxBlockSizeArg::Auto,
        value_parser = parse_max_block_size_arg
    )]
    max_block_size: MaxBlockSizeArg,
    /// Round-0 repair overhead factor, >= 1.0 (rq only).
    #[arg(long, default_value_t = DEFAULT_REPAIR_OVERHEAD)]
    repair_overhead: f64,
    /// Expected RQ round-0 wire loss percentage used to size proactive repair.
    ///
    /// This is intentionally separate from sender pacing. `0` keeps the default
    /// source-first behavior; lossy matrix cells pass their netem loss here.
    #[arg(long = "rq-round0-loss-pct", default_value_t = 0.0)]
    rq_round0_loss_pct: f64,
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
    /// Disable transparent ATP delta planning and force the current full-object
    /// transfer path.
    #[arg(long)]
    no_delta: bool,
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
    /// Maximum RaptorQ source-block size in bytes, `auto`, or `0` (rq/quic only; must match the sender).
    #[arg(
        long,
        default_value_t = MaxBlockSizeArg::Auto,
        value_parser = parse_max_block_size_arg
    )]
    max_block_size: MaxBlockSizeArg,
    /// Round-0 repair overhead factor (rq only).
    #[arg(long, default_value_t = DEFAULT_REPAIR_OVERHEAD)]
    repair_overhead: f64,
    /// Expected RQ round-0 wire loss percentage used to size proactive repair.
    #[arg(long = "rq-round0-loss-pct", default_value_t = 0.0)]
    rq_round0_loss_pct: f64,
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
    /// Disable receiver-side delta package application and state refresh.
    #[arg(long)]
    no_delta: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaxBlockSizeArg {
    Auto,
    Bytes(usize),
}

impl Default for MaxBlockSizeArg {
    fn default() -> Self {
        Self::Auto
    }
}

impl std::fmt::Display for MaxBlockSizeArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => f.write_str("auto"),
            Self::Bytes(bytes) => write!(f, "{bytes}"),
        }
    }
}

impl std::str::FromStr for MaxBlockSizeArg {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        parse_max_block_size_arg(raw)
    }
}

fn parse_max_block_size_arg(raw: &str) -> Result<MaxBlockSizeArg, String> {
    let value = raw.trim();
    if value.eq_ignore_ascii_case("auto") {
        return Ok(MaxBlockSizeArg::Auto);
    }
    let bytes = parse_max_block_size_bytes(value)?;
    if bytes == 0 {
        Ok(MaxBlockSizeArg::Auto)
    } else {
        Ok(MaxBlockSizeArg::Bytes(bytes))
    }
}

fn parse_max_block_size_bytes(value: &str) -> Result<usize, String> {
    let lower = value.to_ascii_lowercase();
    let (digits, multiplier) = [
        ("gib", 1024usize * 1024 * 1024),
        ("gb", 1024usize * 1024 * 1024),
        ("g", 1024usize * 1024 * 1024),
        ("mib", 1024usize * 1024),
        ("mb", 1024usize * 1024),
        ("m", 1024usize * 1024),
        ("kib", 1024usize),
        ("kb", 1024usize),
        ("k", 1024usize),
        ("b", 1usize),
    ]
    .iter()
    .find_map(|(suffix, multiplier)| {
        lower
            .strip_suffix(suffix)
            .map(|digits| (digits, *multiplier))
    })
    .unwrap_or((value, 1usize));

    let count = digits.trim().parse::<usize>().map_err(|_| {
        format!(
            "invalid --max-block-size {value:?}: expected positive bytes, auto, 0, or K/M/G suffix"
        )
    })?;
    count
        .checked_mul(multiplier)
        .ok_or_else(|| format!("invalid --max-block-size {value:?}: byte count overflows usize"))
}

impl MaxBlockSizeArg {
    fn effective(self, symbol_size: u16) -> Result<usize, String> {
        match self {
            Self::Auto => normalize_max_block_size(symbol_size, AUTO_MAX_BLOCK_SIZE),
            Self::Bytes(bytes) => normalize_max_block_size(symbol_size, bytes),
        }
    }

    fn remote_arg(self) -> String {
        self.to_string()
    }
}

fn tcp_config(max_bytes: u64, enable_delta: bool) -> TransferConfig {
    TransferConfig {
        max_transfer_bytes: max_bytes,
        enable_delta,
        ..TransferConfig::default()
    }
}

fn rq_config(
    max_bytes: u64,
    symbol_size: u16,
    streams: usize,
    max_block_size: usize,
    repair_overhead: f64,
    rq_round0_loss_pct: f64,
    tail_drain_ms: u64,
    rq_auth_key_hex: Option<&str>,
    rq_allow_unauthenticated_lab: bool,
) -> Result<RqConfig, String> {
    let max_block_size = normalize_max_block_size(symbol_size, max_block_size)?;
    let round0_loss_target = normalize_loss_pct(rq_round0_loss_pct, "--rq-round0-loss-pct")?;
    let config = RqConfig {
        symbol_size,
        udp_fanout: streams.max(1),
        max_block_size,
        repair_overhead: repair_overhead.max(1.0),
        round0_loss_target,
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

fn normalize_loss_pct(value: f64, flag: &str) -> Result<f64, String> {
    if !value.is_finite() || value < 0.0 || value >= 100.0 {
        return Err(format!("{flag} must be finite and in [0, 100)"));
    }
    Ok(value / 100.0)
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

#[cfg(feature = "tls")]
#[derive(Debug)]
struct QuicCliServerVerifier {
    webpki: Arc<rustls::client::WebPkiServerVerifier>,
    pinned_leafs: Vec<Vec<u8>>,
    signature_algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

#[cfg(feature = "tls")]
impl QuicCliServerVerifier {
    fn new(
        roots: rustls::RootCertStore,
        pinned_leafs: Vec<Vec<u8>>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, asupersync::net::quic_native::tls::QuicTlsError> {
        let signature_algorithms = provider.signature_verification_algorithms;
        let webpki =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|_| {
                    asupersync::net::quic_native::tls::QuicTlsError::CryptoProviderFailure {
                        provider: "rustls-quic-handshake",
                        code: "client_verifier_build_failed",
                    }
                })?;

        Ok(Self {
            webpki,
            pinned_leafs,
            signature_algorithms,
        })
    }

    fn pinned_leaf_matches(&self, end_entity: &rustls::pki_types::CertificateDer<'_>) -> bool {
        self.pinned_leafs
            .iter()
            .any(|pinned| pinned.as_slice() == end_entity.as_ref())
    }
}

#[cfg(feature = "tls")]
impl rustls::client::danger::ServerCertVerifier for QuicCliServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(_) if self.pinned_leaf_matches(end_entity) => {
                verify_quic_cli_pinned_leaf(end_entity, server_name, now)?;
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            Err(webpki_error) => Err(webpki_error),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.signature_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.signature_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.signature_algorithms.supported_schemes()
    }
}

#[cfg(feature = "tls")]
fn rustls_cert_error(error: rustls::CertificateError) -> rustls::Error {
    rustls::Error::InvalidCertificate(error)
}

#[cfg(feature = "tls")]
fn verify_quic_cli_pinned_leaf(
    end_entity: &rustls::pki_types::CertificateDer<'_>,
    server_name: &rustls::pki_types::ServerName<'_>,
    now: rustls::pki_types::UnixTime,
) -> Result<(), rustls::Error> {
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

    let (remaining, cert) = X509Certificate::from_der(end_entity.as_ref())
        .map_err(|_| rustls_cert_error(rustls::CertificateError::BadEncoding))?;
    if !remaining.is_empty() {
        return Err(rustls_cert_error(rustls::CertificateError::BadEncoding));
    }

    let now_secs = i64::try_from(now.as_secs())
        .map_err(|_| rustls_cert_error(rustls::CertificateError::BadEncoding))?;
    let validity = cert.validity();
    if now_secs < validity.not_before.timestamp() {
        return Err(rustls_cert_error(rustls::CertificateError::NotValidYet));
    }
    if now_secs > validity.not_after.timestamp() {
        return Err(rustls_cert_error(rustls::CertificateError::Expired));
    }

    let eku = cert
        .extended_key_usage()
        .map_err(|_| rustls_cert_error(rustls::CertificateError::BadEncoding))?
        .ok_or_else(|| rustls_cert_error(rustls::CertificateError::InvalidPurpose))?;
    if !eku.value.server_auth {
        return Err(rustls_cert_error(rustls::CertificateError::InvalidPurpose));
    }

    let san = cert
        .subject_alternative_name()
        .map_err(|_| rustls_cert_error(rustls::CertificateError::BadEncoding))?
        .ok_or_else(|| rustls_cert_error(rustls::CertificateError::NotValidForName))?;

    let name_matches = match server_name {
        rustls::pki_types::ServerName::DnsName(_) => {
            let expected = server_name.to_str();
            san.value.general_names.iter().any(|name| match name {
                GeneralName::DNSName(dns) => dns.eq_ignore_ascii_case(expected.as_ref()),
                _ => false,
            })
        }
        rustls::pki_types::ServerName::IpAddress(ip) => {
            let expected = std::net::IpAddr::from(*ip);
            san.value.general_names.iter().any(|name| match name {
                GeneralName::IPAddress(raw) => match expected {
                    std::net::IpAddr::V4(addr) => *raw == addr.octets().as_slice(),
                    std::net::IpAddr::V6(addr) => *raw == addr.octets().as_slice(),
                },
                _ => false,
            })
        }
        _ => false,
    };

    if name_matches {
        Ok(())
    } else {
        Err(rustls_cert_error(rustls::CertificateError::NotValidForName))
    }
}

#[cfg(feature = "tls")]
fn quic_cli_client_config(
    roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    alpn: Vec<Vec<u8>>,
) -> Result<Arc<rustls::ClientConfig>, asupersync::net::quic_native::tls::QuicTlsError> {
    use asupersync::net::quic_native::handshake_driver::client_config;

    if roots.is_empty() {
        return client_config(roots, alpn);
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut root_store = rustls::RootCertStore::empty();
    let pinned_leafs = roots
        .iter()
        .map(|cert| cert.as_ref().to_vec())
        .collect::<Vec<_>>();
    for cert in roots {
        root_store.add(cert).map_err(|_| {
            asupersync::net::quic_native::tls::QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "client_root_add_failed",
            }
        })?;
    }
    let verifier = QuicCliServerVerifier::new(root_store, pinned_leafs, provider.clone())?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(
            |_| asupersync::net::quic_native::tls::QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "client_protocol_versions",
            },
        )?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    Ok(Arc::new(config))
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

#[cfg(feature = "tls")]
fn quic_server_name(name: String) -> Result<rustls::pki_types::ServerName<'static>, String> {
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        return Ok(rustls::pki_types::ServerName::from(ip));
    }

    rustls::pki_types::ServerName::try_from(name.clone())
        .map_err(|e| format!("invalid --server-name {name:?}: {e}"))
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
    use asupersync::net::quic_native::handshake_driver::ATP_QUIC_ALPN;

    let roots = match args.ca.as_deref() {
        Some(path) => load_cert_chain(path)?,
        None => Vec::new(),
    };
    let name = args
        .server_name
        .clone()
        .unwrap_or_else(|| default_server_name(&args.target));
    let server_name = quic_server_name(name)?;
    let config = quic_cli_client_config(roots, vec![ATP_QUIC_ALPN.to_vec()])
        .map_err(|e| format!("build QUIC client TLS config: {e:?}"))?;

    let base = QuicConfig {
        symbol_size: args.symbol_size,
        max_block_size: args.max_block_size.effective(args.symbol_size)?,
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
        max_block_size: args.max_block_size.effective(args.symbol_size)?,
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

fn throughput_bytes_per_sec(bytes: u64, elapsed: Option<Duration>) -> Option<u64> {
    let elapsed = elapsed?;
    let micros = elapsed.as_micros();
    if micros == 0 {
        return None;
    }
    let rate = u128::from(bytes).saturating_mul(1_000_000) / micros;
    Some(rate.min(u128::from(u64::MAX)) as u64)
}

fn elapsed_micros(elapsed: Option<Duration>) -> Option<u64> {
    elapsed.map(|duration| {
        let micros = duration.as_micros();
        micros.min(u128::from(u64::MAX)) as u64
    })
}

fn atp_metrics_json(
    bytes: u64,
    symbols_sent: Option<u64>,
    symbols_accepted: Option<u64>,
    feedback_rounds: u32,
    decode_count: Option<u64>,
    decode_micros: Option<u64>,
    chosen_fanout: usize,
    elapsed: Option<Duration>,
) -> serde_json::Value {
    serde_json::json!({
        "bytes": bytes,
        "elapsed_micros": elapsed_micros(elapsed),
        "throughput_bytes_per_sec": throughput_bytes_per_sec(bytes, elapsed),
        "symbols_sent": symbols_sent,
        "symbols_accepted": symbols_accepted,
        "feedback_rounds": feedback_rounds,
        "decode_count": decode_count,
        "decode_micros": decode_micros,
        "chosen_fanout": chosen_fanout,
        "ring_peak_occupancy": Option::<u64>::None,
        "ring_avg_occupancy": Option::<u64>::None,
        "drop_count": Option::<u64>::None,
        "park_count": Option::<u64>::None,
    })
}

fn print_atp_metrics_line(
    direction: &str,
    transport: Transport,
    bytes: u64,
    symbols_sent: Option<u64>,
    symbols_accepted: Option<u64>,
    feedback_rounds: u32,
    decode_micros: Option<u64>,
    chosen_fanout: usize,
    elapsed: Option<Duration>,
) {
    let throughput = throughput_bytes_per_sec(bytes, elapsed)
        .map_or_else(|| "n/a".to_string(), |value| value.to_string());
    let symbols_sent = symbols_sent.map_or_else(|| "n/a".to_string(), |value| value.to_string());
    let symbols_accepted =
        symbols_accepted.map_or_else(|| "n/a".to_string(), |value| value.to_string());
    let decode_micros = decode_micros.map_or_else(|| "n/a".to_string(), |value| value.to_string());
    eprintln!(
        "[atp] progress metrics direction={direction} transport={} bytes={bytes} \
         throughput_bytes_per_sec={throughput} symbols_sent={symbols_sent} \
         symbols_accepted={symbols_accepted} feedback_rounds={feedback_rounds} \
         decode_micros={decode_micros} fanout={chosen_fanout} \
         ring_peak_occupancy=n/a ring_avg_occupancy=n/a drop_count=n/a park_count=n/a",
        transport.cli_arg(),
    );
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
        Ok(addr) => run_send_to_addr(args, addr, true),
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
    let cfg = tcp_config(args.max_bytes, false);
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

fn annotate_direct_delta_package_report(
    report: &mut serde_json::Value,
    plan: &DeltaResyncPlan,
    package_payload_bytes: u64,
    subdelta_chunks: usize,
) {
    if let Some(object) = report.as_object_mut() {
        object.insert(
            "delta".to_string(),
            serde_json::json!({
                "mode": "delta_chunks",
                "negotiation": "direct_receiver_state_sidecar",
                "sender_merkle_root": plan.sender_merkle_root.to_string(),
                "receiver_merkle_root": plan.receiver_merkle_root.as_ref().map(ToString::to_string),
                "shared_chunks": plan.shared_chunks,
                "stale_chunks": plan.stale_chunks.len(),
                "missing_chunks": plan.missing_chunks.len(),
                "missing_bytes": plan.missing_bytes,
                "package_payload_bytes": package_payload_bytes,
                "subdelta_chunks": subdelta_chunks,
            }),
        );
    }
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

fn run_send_to_addr(
    mut args: SendArgs,
    addr: SocketAddr,
    use_direct_delta_probe: bool,
) -> Result<(), String> {
    let mut direct_delta_plan = None;
    if use_direct_delta_probe && let Some(delta) = prepare_direct_delta_send(&args, addr)? {
        match delta {
            DeltaPreparedSend::AlreadyInSync(report) => {
                print_json(&report);
                return Ok(());
            }
            DeltaPreparedSend::Package {
                package_root,
                plan,
                package_payload_bytes,
                subdelta_chunks,
            } => {
                eprintln!(
                    "[atp] delta planner: direct receiver state selected {} chunk(s), {} logical byte(s), {} package byte(s), {} sub-delta chunk(s), shared {} chunk(s)",
                    plan.missing_chunks.len(),
                    plan.missing_bytes,
                    package_payload_bytes,
                    subdelta_chunks,
                    plan.shared_chunks
                );
                args.source = package_root;
                direct_delta_plan = Some((plan, package_payload_bytes, subdelta_chunks));
            }
        }
    }

    let runtime = build_runtime(args.workers)?;
    let mut report = if args.transport == Transport::Auto {
        run_send_auto_to_addr(&runtime, &args, addr)?
    } else {
        send_to_addr_with_transport(&runtime, &args, args.transport, addr)?
    };
    if let Some((plan, package_payload_bytes, subdelta_chunks)) = direct_delta_plan.as_ref() {
        annotate_direct_delta_package_report(
            &mut report,
            plan,
            *package_payload_bytes,
            *subdelta_chunks,
        );
    }
    print_json(&report);
    Ok(())
}

fn run_send_auto_to_addr(
    runtime: &asupersync::runtime::Runtime,
    args: &SendArgs,
    addr: SocketAddr,
) -> Result<serde_json::Value, String> {
    let mut attempts = Vec::new();
    for transport in Transport::auto_fallback_order(!args.no_delta)
        .iter()
        .copied()
    {
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
            let cfg = tcp_config(args.max_bytes, !args.no_delta);
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
                                "[atp] progress transport=tcp pct={:>3.0} bytes={done}/{total} \
                                 throughput_bytes_per_sec={:.0}{eta} fanout=1",
                                snap.fraction * 100.0,
                                snap.rate_bytes_per_sec,
                            );
                        },
                    )
                    .await
                }))
                .map_err(|e: TransportError| e.to_string())?;
            let elapsed = start.elapsed();
            print_atp_metrics_line(
                "send",
                Transport::Tcp,
                report.bytes_sent,
                Some(report.symbols_sent),
                Some(report.receipt.symbols_accepted),
                report.feedback_rounds,
                Some(report.receipt.decode_micros),
                1,
                Some(elapsed),
            );
            Ok(tcp_send_json(&report, Some(elapsed)))
        }
        Transport::Rq => {
            let cfg = rq_config(
                args.max_bytes,
                args.symbol_size,
                args.streams,
                args.max_block_size.effective(args.symbol_size)?,
                args.repair_overhead,
                args.rq_round0_loss_pct,
                args.rq_tail_drain_ms,
                args.rq_auth_key_hex.as_deref(),
                args.rq_allow_unauthenticated_lab,
            )?;
            let chosen_fanout = cfg.udp_fanout.max(1);
            let start = Instant::now();
            let report = runtime
                .block_on(runtime.handle().spawn(async move {
                    let cx = Cx::current().expect("sender cx");
                    transport_rq::send_path(&cx, addr, &source, cfg, &peer_id).await
                }))
                .map_err(|e| e.to_string())?;
            let elapsed = start.elapsed();
            print_atp_metrics_line(
                "send",
                Transport::Rq,
                report.bytes_sent,
                Some(report.symbols_sent),
                Some(report.receipt.symbols_accepted),
                report.feedback_rounds,
                None,
                chosen_fanout,
                Some(elapsed),
            );
            Ok(rq_send_json(&report, chosen_fanout, Some(elapsed)))
        }
        Transport::Quic => {
            #[cfg(feature = "tls")]
            {
                let cfg = quic_config_send(args)?;
                let chosen_fanout = cfg.datagram_fanout.max(1);
                let start = Instant::now();
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
                let elapsed = start.elapsed();
                print_atp_metrics_line(
                    "send",
                    Transport::Quic,
                    report.bytes_sent,
                    Some(report.symbols_sent),
                    Some(report.receipt.symbols_accepted),
                    report.feedback_rounds,
                    Some(report.receipt.decode_micros),
                    chosen_fanout,
                    Some(elapsed),
                );
                Ok(quic_send_json(&report, chosen_fanout, Some(elapsed)))
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
    let delta_package = if args.no_delta {
        None
    } else {
        prepare_delta_ssh_send(&args, remote)?
    };
    if let Some(delta) = delta_package {
        match delta {
            DeltaPreparedSend::AlreadyInSync(report) => {
                print_json(&report);
                return Ok(());
            }
            DeltaPreparedSend::Package {
                package_root,
                plan,
                package_payload_bytes,
                subdelta_chunks,
            } => {
                eprintln!(
                    "[atp] delta planner: sending {} chunk(s), {} logical byte(s), {} package byte(s), {} sub-delta chunk(s), shared {} chunk(s)",
                    plan.missing_chunks.len(),
                    plan.missing_bytes,
                    package_payload_bytes,
                    subdelta_chunks,
                    plan.shared_chunks
                );
                args.source = package_root;
            }
        }
    }
    let data_target = socket_target(&data_host, args.remote_listen.port());
    let addr = resolve(&data_target)?;
    let mut child = spawn_remote_receiver(&args, remote, rq_auth.as_ref())?;
    let stderr_log = wait_for_remote_ready(
        &mut child,
        Duration::from_secs(args.ssh_ready_timeout_secs.max(1)),
    )?;

    let send_result = run_send_to_addr(args, addr, false);
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

#[derive(Debug)]
enum DeltaPreparedSend {
    AlreadyInSync(serde_json::Value),
    Package {
        package_root: PathBuf,
        plan: DeltaResyncPlan,
        package_payload_bytes: u64,
        subdelta_chunks: usize,
    },
}

#[derive(Debug)]
struct DeltaSourceSnapshot {
    manifest: PersistentChunkManifest,
    chunks_by_content: BTreeMap<String, Vec<u8>>,
    object_sha256_hex: String,
    file_count: usize,
    logical_file_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeltaCliState {
    schema: String,
    manifest_hex: String,
    object_sha256_hex: String,
    chunk_count: usize,
    logical_file_bytes: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    chunk_signatures: Vec<DeltaChunkSignatureState>,
}

impl DeltaCliState {
    fn manifest(&self) -> Result<PersistentChunkManifest, String> {
        if self.schema != DELTA_STATE_SCHEMA {
            return Err(format!("unsupported delta state schema: {}", self.schema));
        }
        let bytes = hex::decode(&self.manifest_hex)
            .map_err(|err| format!("decode delta state manifest hex: {err}"))?;
        PersistentChunkManifest::from_canonical_bytes(&bytes)
            .map_err(|err| format!("decode delta state manifest: {err}"))
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeltaChunkSignatureState {
    content_id_hex: String,
    size_bytes: u64,
    signature: SubBlockSignature,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeltaSubchunkSignatureRequest {
    schema: String,
    chunks: Vec<DeltaSubchunkSignatureRequestChunk>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeltaSubchunkSignatureRequestChunk {
    content_id_hex: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeltaSubchunkSignatureResponse {
    schema: String,
    signatures: Vec<DeltaChunkSignatureState>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeltaPackageMetadata {
    schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_manifest_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_manifest_b64: Option<String>,
    object_sha256_hex: String,
    #[serde(default)]
    missing_chunks: Vec<DeltaPackageChunkMetadata>,
    #[serde(default)]
    subdelta_chunks: Vec<DeltaPackageSubdeltaMetadata>,
    #[serde(default)]
    repeated_chunks: Vec<DeltaPackageRepeatedChunkMetadata>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeltaPackageChunkMetadata {
    content_id_hex: String,
    size_bytes: u64,
    file_name: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeltaPackageSubdeltaMetadata {
    target_content_id_hex: String,
    target_sha256_hex: String,
    target_size_bytes: u64,
    base_content_id_hex: String,
    base_size_bytes: u64,
    ops_file_name: String,
    ops_wire_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DeltaPackageRepeatedChunkMetadata {
    target_content_id_hex: String,
    target_size_bytes: u64,
}

#[derive(Debug)]
struct DeltaPackageBuild {
    whole_chunks: Vec<DeltaWholeChunkPackage>,
    subdelta_chunks: Vec<DeltaSubdeltaPackage>,
    repeated_chunks: Vec<DeltaRepeatedChunkPackage>,
    payload_bytes: u64,
}

#[derive(Debug)]
struct DeltaWholeChunkPackage {
    chunk: CasChunkRef,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct DeltaSubdeltaPackage {
    target_chunk: CasChunkRef,
    target_sha256_hex: String,
    base_chunk: CasChunkRef,
    encoded_ops: Vec<u8>,
    ops_wire_bytes: u64,
}

#[derive(Debug)]
struct DeltaRepeatedChunkPackage {
    chunk: CasChunkRef,
}

#[derive(Debug)]
struct DeltaPackageWrite {
    package_root: PathBuf,
    package_payload_bytes: u64,
    subdelta_chunks: usize,
}

#[derive(Debug)]
struct DeltaTreeFile {
    rel_path: String,
    bytes: Vec<u8>,
}

fn prepare_delta_ssh_send(
    args: &SendArgs,
    remote: &RemoteTarget,
) -> Result<Option<DeltaPreparedSend>, String> {
    let receiver_state = match fetch_remote_delta_state(args, remote) {
        Ok(Some(state)) => state,
        Ok(None) => {
            eprintln!("[atp] delta planner: no receiver state; using full-object transfer");
            return Ok(None);
        }
        Err(err) => {
            eprintln!(
                "[atp] delta planner: receiver state unavailable ({err}); using full-object transfer"
            );
            return Ok(None);
        }
    };
    prepare_delta_send_from_state(args, receiver_state, None)
}

fn prepare_direct_delta_send(
    args: &SendArgs,
    addr: SocketAddr,
) -> Result<Option<DeltaPreparedSend>, String> {
    if args.no_delta
        || !matches!(
            args.transport,
            Transport::Auto | Transport::Rq | Transport::Quic
        )
    {
        return Ok(None);
    }

    let Some(state_addr) = delta_state_addr(addr) else {
        eprintln!(
            "[atp] delta planner: no receiver state sidecar port; using full-object transfer"
        );
        return Ok(None);
    };
    let receiver_state = match fetch_direct_delta_state(state_addr) {
        Ok(Some(state)) => state,
        Ok(None) => {
            eprintln!(
                "[atp] delta planner: receiver state sidecar {state_addr} returned no state; using full-object transfer"
            );
            return Ok(None);
        }
        Err(err) => {
            eprintln!(
                "[atp] delta planner: receiver state sidecar {state_addr} unavailable ({err}); using full-object transfer"
            );
            return Ok(None);
        }
    };
    prepare_delta_send_from_state(args, receiver_state, Some(state_addr))
}

fn prepare_delta_send_from_state(
    args: &SendArgs,
    receiver_state: DeltaCliState,
    lazy_signature_addr: Option<SocketAddr>,
) -> Result<Option<DeltaPreparedSend>, String> {
    let receiver_manifest = match receiver_state.manifest() {
        Ok(manifest) => manifest,
        Err(err) => {
            eprintln!(
                "[atp] delta planner: receiver state unreadable ({err}); using full-object transfer"
            );
            return Ok(None);
        }
    };
    let snapshot = match build_delta_source_snapshot(&args.source) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            eprintln!(
                "[atp] delta planner: source is not delta-packable ({err}); using full-object transfer"
            );
            return Ok(None);
        }
    };

    let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver_manifest);
    let plan = plan_incremental_resync_with_receiver_coverage(
        &snapshot.manifest,
        Some(&receiver_manifest),
        &receiver_coverage,
    );
    match plan.mode {
        DeltaResyncMode::AlreadyInSync => {
            let report = serde_json::json!({
                "event": "atp_send",
                "requested_transport": args.transport.cli_arg(),
                "delta": {
                    "mode": "already_in_sync",
                    "sender_merkle_root": snapshot.manifest.merkle_root.to_string(),
                    "receiver_merkle_root": plan.receiver_merkle_root.as_ref().map(ToString::to_string),
                    "shared_chunks": plan.shared_chunks,
                    "missing_chunks": 0,
                    "missing_bytes": 0,
                },
                "committed": true,
                "bytes_sent": 0,
                "files": snapshot.file_count,
                "logical_file_bytes": snapshot.logical_file_bytes,
                "sha256": snapshot.object_sha256_hex,
                "peer": args.peer_id,
            });
            Ok(Some(DeltaPreparedSend::AlreadyInSync(report)))
        }
        DeltaResyncMode::DeltaChunks => {
            let receiver_signatures = receiver_subchunk_signatures_for_plan(
                &plan,
                &receiver_manifest,
                &receiver_state,
                lazy_signature_addr,
            )?;
            let package =
                create_delta_package(&snapshot, &plan, &receiver_manifest, &receiver_signatures)?;
            Ok(Some(DeltaPreparedSend::Package {
                package_root: package.package_root,
                plan,
                package_payload_bytes: package.package_payload_bytes,
                subdelta_chunks: package.subdelta_chunks,
            }))
        }
        DeltaResyncMode::FullObjectFallback => {
            if plan.fallback_reason == Some(asupersync::atp::delta::DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject) {
                let receiver_signatures = receiver_subchunk_signatures_for_plan(
                    &plan,
                    &receiver_manifest,
                    &receiver_state,
                    lazy_signature_addr,
                )?;
                let package_build =
                    build_delta_package(&snapshot, &plan, &receiver_manifest, &receiver_signatures)?;
                if package_build.payload_bytes < snapshot.manifest.total_size_bytes {
                    let mut subdelta_plan = plan.clone();
                    subdelta_plan.mode = DeltaResyncMode::DeltaChunks;
                    subdelta_plan.fallback_reason = None;
                    let package = write_delta_package(&snapshot, &package_build)?;
                    return Ok(Some(DeltaPreparedSend::Package {
                        package_root: package.package_root,
                        plan: subdelta_plan,
                        package_payload_bytes: package.package_payload_bytes,
                        subdelta_chunks: package.subdelta_chunks,
                    }));
                }
            }
            eprintln!(
                "[atp] delta planner: full-object fallback ({:?}); missing {} of {} bytes",
                plan.fallback_reason, plan.missing_bytes, snapshot.manifest.total_size_bytes,
            );
            Ok(None)
        }
    }
}

fn fetch_remote_delta_state(
    args: &SendArgs,
    remote: &RemoteTarget,
) -> Result<Option<DeltaCliState>, String> {
    let state_path = remote_delta_state_path(&remote.remote_path);
    let mut command = ssh_command(args, &remote.ssh_host);
    command.arg(format!(
        "if test -r {}; then cat {}; fi",
        shell_quote(&state_path),
        shell_quote(&state_path)
    ));
    let output = command
        .output()
        .map_err(|err| format!("fetch remote delta state via ssh: {err}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(trimmed)
        .map(Some)
        .map_err(|err| format!("parse remote delta state {}: {err}", state_path))
}

fn fetch_direct_delta_state(state_addr: SocketAddr) -> Result<Option<DeltaCliState>, String> {
    let mut stream = std::net::TcpStream::connect_timeout(&state_addr, Duration::from_millis(750))
        .map_err(|err| format!("connect: {err}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("set read timeout: {err}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("set write timeout: {err}"))?;

    let mut body = String::new();
    stream
        .read_to_string(&mut body)
        .map_err(|err| format!("read state: {err}"))?;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(trimmed)
        .map(Some)
        .map_err(|err| format!("parse direct receiver delta state: {err}"))
}

fn fetch_direct_subchunk_signatures(
    state_addr: SocketAddr,
    chunks: &[CasChunkRef],
) -> Result<Vec<DeltaChunkSignatureState>, String> {
    if chunks.is_empty() {
        return Ok(Vec::new());
    }

    let mut stream = std::net::TcpStream::connect_timeout(&state_addr, Duration::from_millis(750))
        .map_err(|err| format!("connect: {err}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("set read timeout: {err}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("set write timeout: {err}"))?;

    let request = DeltaSubchunkSignatureRequest {
        schema: DELTA_SUBCHUNK_SIGNATURE_REQUEST_SCHEMA.to_string(),
        chunks: chunks
            .iter()
            .map(|chunk| DeltaSubchunkSignatureRequestChunk {
                content_id_hex: chunk.content_id.to_hex(),
                size_bytes: chunk.size_bytes,
            })
            .collect(),
    };
    serde_json::to_writer(&mut stream, &request)
        .map_err(|err| format!("write subchunk signature request: {err}"))?;
    stream
        .write_all(b"\n")
        .and_then(|_| stream.flush())
        .map_err(|err| format!("finish subchunk signature request: {err}"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|err| format!("shutdown subchunk signature request: {err}"))?;

    let mut body = String::new();
    stream
        .read_to_string(&mut body)
        .map_err(|err| format!("read subchunk signature response: {err}"))?;
    let response: DeltaSubchunkSignatureResponse = serde_json::from_str(body.trim())
        .map_err(|err| format!("parse subchunk signature response: {err}"))?;
    if response.schema != DELTA_SUBCHUNK_SIGNATURE_RESPONSE_SCHEMA {
        return Err(format!(
            "unsupported subchunk signature response schema: {}",
            response.schema
        ));
    }
    Ok(response.signatures)
}

fn remote_delta_state_path(remote_path: &str) -> String {
    let base = remote_path.trim_end_matches('/');
    if base.is_empty() {
        format!("{DELTA_STATE_DIR}/{DELTA_STATE_FILE}")
    } else {
        format!("{base}/{DELTA_STATE_DIR}/{DELTA_STATE_FILE}")
    }
}

fn create_delta_package(
    snapshot: &DeltaSourceSnapshot,
    plan: &DeltaResyncPlan,
    receiver_manifest: &PersistentChunkManifest,
    receiver_signatures: &[ReceiverSubchunkSignature],
) -> Result<DeltaPackageWrite, String> {
    let package = build_delta_package(snapshot, plan, receiver_manifest, receiver_signatures)?;
    write_delta_package(snapshot, &package)
}

fn build_delta_package(
    snapshot: &DeltaSourceSnapshot,
    plan: &DeltaResyncPlan,
    receiver_manifest: &PersistentChunkManifest,
    receiver_signatures: &[ReceiverSubchunkSignature],
) -> Result<DeltaPackageBuild, String> {
    let sender_store = delta_store_from_snapshot(snapshot)?;
    let send_plan =
        build_delta_resync_send_plan(plan, &sender_store, receiver_manifest, receiver_signatures)
            .map_err(|err| format!("build delta send plan: {err}"))?;

    let mut whole_chunks = Vec::new();
    let mut subdelta_chunks = Vec::new();
    let mut repeated_chunks = Vec::new();

    for item in send_plan.items {
        match item {
            DeltaResyncSendItem::WholeChunk { chunk, payload } => {
                whole_chunks.push(DeltaWholeChunkPackage { chunk, payload });
            }
            DeltaResyncSendItem::SubchunkOps {
                target_chunk,
                base_chunk,
                target_sha256,
                encoded_ops,
            } => {
                let ops_wire_bytes = u64::try_from(encoded_ops.len())
                    .map_err(|_| "sub-delta op stream exceeds u64::MAX".to_string())?;
                subdelta_chunks.push(DeltaSubdeltaPackage {
                    target_chunk,
                    target_sha256_hex: hex::encode(target_sha256),
                    base_chunk,
                    encoded_ops,
                    ops_wire_bytes,
                });
            }
            DeltaResyncSendItem::RepeatedChunk { chunk, .. } => {
                repeated_chunks.push(DeltaRepeatedChunkPackage { chunk });
            }
        }
    }

    Ok(DeltaPackageBuild {
        whole_chunks,
        subdelta_chunks,
        repeated_chunks,
        payload_bytes: send_plan.payload_bytes,
    })
}

fn receiver_subchunk_signatures_for_plan(
    plan: &DeltaResyncPlan,
    receiver_manifest: &PersistentChunkManifest,
    receiver_state: &DeltaCliState,
    lazy_signature_addr: Option<SocketAddr>,
) -> Result<Vec<ReceiverSubchunkSignature>, String> {
    let candidates = receiver_subchunk_signature_candidates(plan, receiver_manifest)?;
    let mut signatures =
        receiver_subchunk_signatures_from_states(&candidates, &receiver_state.chunk_signatures);
    let mut signed_keys = signatures
        .iter()
        .map(|entry| (entry.chunk.content_id.to_hex(), entry.chunk.size_bytes))
        .collect::<std::collections::BTreeSet<_>>();
    let missing_candidates = candidates
        .iter()
        .filter(|chunk| !signed_keys.contains(&(chunk.content_id.to_hex(), chunk.size_bytes)))
        .cloned()
        .collect::<Vec<_>>();

    if let Some(addr) = lazy_signature_addr.filter(|_| !missing_candidates.is_empty()) {
        match fetch_direct_subchunk_signatures(addr, &missing_candidates) {
            Ok(lazy_states) => {
                for signature in
                    receiver_subchunk_signatures_from_states(&missing_candidates, &lazy_states)
                {
                    let key = (
                        signature.chunk.content_id.to_hex(),
                        signature.chunk.size_bytes,
                    );
                    if signed_keys.insert(key) {
                        signatures.push(signature);
                    }
                }
            }
            Err(err) => {
                eprintln!(
                    "[atp] delta planner: lazy receiver subchunk signatures unavailable ({err}); using whole changed chunks where needed"
                );
            }
        }
    }

    Ok(signatures)
}

fn receiver_subchunk_signature_candidates(
    plan: &DeltaResyncPlan,
    receiver_manifest: &PersistentChunkManifest,
) -> Result<Vec<CasChunkRef>, String> {
    let mut candidates = BTreeMap::<(String, u64), CasChunkRef>::new();
    for target in &plan.missing_chunks {
        let target_index = usize::try_from(target.index)
            .map_err(|_| "delta target chunk index exceeds usize::MAX".to_string())?;
        let same_index_base = receiver_manifest.chunks.get(target_index);
        for base in receiver_manifest.chunks.iter().filter(|base| {
            delta_chunk_ranges_overlap(target, base)
                || same_index_base
                    .is_some_and(|same_index| delta_chunk_refs_match(same_index, base))
        }) {
            if base.content_id == target.content_id {
                continue;
            }
            candidates
                .entry((base.content_id.to_hex(), base.size_bytes))
                .or_insert_with(|| base.clone());
        }
    }
    Ok(candidates.into_values().collect())
}

fn delta_chunk_ranges_overlap(left: &CasChunkRef, right: &CasChunkRef) -> bool {
    let left_end = left.byte_offset.saturating_add(left.size_bytes);
    let right_end = right.byte_offset.saturating_add(right.size_bytes);
    left.byte_offset < right_end && right.byte_offset < left_end
}

fn delta_chunk_refs_match(left: &CasChunkRef, right: &CasChunkRef) -> bool {
    left.content_id == right.content_id && left.size_bytes == right.size_bytes
}

fn receiver_subchunk_signatures_from_states(
    candidates: &[CasChunkRef],
    states: &[DeltaChunkSignatureState],
) -> Vec<ReceiverSubchunkSignature> {
    candidates
        .iter()
        .filter_map(|chunk| {
            let content_id_hex = chunk.content_id.to_hex();
            states
                .iter()
                .find(|entry| {
                    entry.content_id_hex == content_id_hex && entry.size_bytes == chunk.size_bytes
                })
                .map(|entry| ReceiverSubchunkSignature {
                    chunk: chunk.clone(),
                    signature: entry.signature.clone(),
                })
        })
        .collect()
}

fn delta_store_from_snapshot(snapshot: &DeltaSourceSnapshot) -> Result<DeltaChunkStore, String> {
    let mut store = DeltaChunkStore::new();
    for chunk in &snapshot.manifest.chunks {
        let content_id_hex = chunk.content_id.to_hex();
        let payload = snapshot
            .chunks_by_content
            .get(&content_id_hex)
            .ok_or_else(|| format!("source CAS missing planned chunk {content_id_hex}"))?;
        let payload_len = u64::try_from(payload.len())
            .map_err(|_| "delta chunk payload length exceeds u64::MAX".to_string())?;
        if payload_len != chunk.size_bytes || ContentId::from_bytes(payload) != chunk.content_id {
            return Err(format!(
                "source CAS payload does not match planned chunk {content_id_hex}"
            ));
        }
        store
            .insert(payload)
            .map_err(|err| format!("insert sender delta chunk: {err}"))?;
    }
    Ok(store)
}

fn write_delta_package(
    snapshot: &DeltaSourceSnapshot,
    package: &DeltaPackageBuild,
) -> Result<DeltaPackageWrite, String> {
    let package_root = create_unique_delta_package_root(&snapshot.object_sha256_hex)?;
    let chunk_dir = package_root.join(DELTA_CHUNK_DIR);
    fs::create_dir(&chunk_dir).map_err(|err| {
        format!(
            "create delta package chunk dir {}: {err}",
            chunk_dir.display()
        )
    })?;
    let subchunk_dir = package_root.join(DELTA_SUBCHUNK_DIR);
    if !package.subdelta_chunks.is_empty() {
        fs::create_dir(&subchunk_dir).map_err(|err| {
            format!(
                "create delta package subchunk dir {}: {err}",
                subchunk_dir.display()
            )
        })?;
    }

    let mut missing_chunks = Vec::with_capacity(package.whole_chunks.len());
    for whole in &package.whole_chunks {
        let chunk = &whole.chunk;
        let content_id_hex = chunk.content_id.to_hex();
        let file_name = format!("{content_id_hex}.chunk");
        let path = chunk_dir.join(&file_name);
        let mut file = fs::File::create(&path)
            .map_err(|err| format!("create delta chunk {}: {err}", path.display()))?;
        file.write_all(&whole.payload)
            .map_err(|err| format!("write delta chunk {}: {err}", path.display()))?;
        missing_chunks.push(DeltaPackageChunkMetadata {
            content_id_hex,
            size_bytes: chunk.size_bytes,
            file_name,
        });
    }

    let mut subdelta_chunks = Vec::with_capacity(package.subdelta_chunks.len());
    for subdelta in &package.subdelta_chunks {
        let target_content_id_hex = subdelta.target_chunk.content_id.to_hex();
        let base_content_id_hex = subdelta.base_chunk.content_id.to_hex();
        let file_name = format!(
            "{target_content_id_hex}-from-{}.subdelta.ops",
            &base_content_id_hex[..16]
        );
        let path = subchunk_dir.join(&file_name);
        let mut file = fs::File::create(&path)
            .map_err(|err| format!("create delta subchunk ops {}: {err}", path.display()))?;
        file.write_all(&subdelta.encoded_ops)
            .map_err(|err| format!("write delta subchunk ops {}: {err}", path.display()))?;
        subdelta_chunks.push(DeltaPackageSubdeltaMetadata {
            target_content_id_hex,
            target_sha256_hex: subdelta.target_sha256_hex.clone(),
            target_size_bytes: subdelta.target_chunk.size_bytes,
            base_content_id_hex,
            base_size_bytes: subdelta.base_chunk.size_bytes,
            ops_file_name: file_name,
            ops_wire_bytes: subdelta.ops_wire_bytes,
        });
    }

    let repeated_chunks = package
        .repeated_chunks
        .iter()
        .map(|repeated| DeltaPackageRepeatedChunkMetadata {
            target_content_id_hex: repeated.chunk.content_id.to_hex(),
            target_size_bytes: repeated.chunk.size_bytes,
        })
        .collect();

    let target_manifest_bytes = snapshot.manifest.to_canonical_bytes();
    let (target_manifest_hex, target_manifest_b64) =
        encode_delta_package_target_manifest(&target_manifest_bytes);
    let metadata = DeltaPackageMetadata {
        schema: DELTA_PACKAGE_SCHEMA.to_string(),
        target_manifest_hex,
        target_manifest_b64,
        object_sha256_hex: snapshot.object_sha256_hex.clone(),
        missing_chunks,
        subdelta_chunks,
        repeated_chunks,
    };
    let manifest_path = package_root.join(DELTA_PACKAGE_FILE);
    let mut file = fs::File::create(&manifest_path).map_err(|err| {
        format!(
            "create delta package manifest {}: {err}",
            manifest_path.display()
        )
    })?;
    serde_json::to_writer(&mut file, &metadata).map_err(|err| {
        format!(
            "write delta package manifest {}: {err}",
            manifest_path.display()
        )
    })?;
    file.write_all(b"\n").map_err(|err| {
        format!(
            "finish delta package manifest {}: {err}",
            manifest_path.display()
        )
    })?;

    Ok(DeltaPackageWrite {
        package_root,
        package_payload_bytes: package.payload_bytes,
        subdelta_chunks: package.subdelta_chunks.len(),
    })
}

fn encode_delta_package_target_manifest(bytes: &[u8]) -> (Option<String>, Option<String>) {
    let manifest_hex = hex::encode(bytes);
    let manifest_b64 = STANDARD.encode(bytes);
    if manifest_b64.len() < manifest_hex.len() {
        (None, Some(manifest_b64))
    } else {
        (Some(manifest_hex), None)
    }
}

fn decode_delta_package_target_manifest(
    metadata: &DeltaPackageMetadata,
) -> Result<PersistentChunkManifest, String> {
    let target_manifest_bytes = if let Some(encoded) = &metadata.target_manifest_b64 {
        STANDARD
            .decode(encoded)
            .map_err(|err| format!("decode delta package target manifest base64: {err}"))?
    } else if let Some(encoded) = &metadata.target_manifest_hex {
        hex::decode(encoded)
            .map_err(|err| format!("decode delta package target manifest: {err}"))?
    } else {
        return Err("delta package target manifest is missing".to_string());
    };
    PersistentChunkManifest::from_canonical_bytes(&target_manifest_bytes)
        .map_err(|err| format!("decode delta package target manifest: {err}"))
}

fn create_unique_delta_package_root(object_sha256_hex: &str) -> Result<PathBuf, String> {
    let short = object_sha256_hex.get(..16).unwrap_or(object_sha256_hex);
    for attempt in 0..32u32 {
        let nonce = unique_micros();
        let path = env::temp_dir().join(format!("{DELTA_PACKAGE_PREFIX}{short}-{nonce}-{attempt}"));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "create delta package root {}: {err}",
                    path.display()
                ));
            }
        }
    }
    Err("could not allocate a unique delta package directory".to_string())
}

fn build_delta_source_snapshot(source: &Path) -> Result<DeltaSourceSnapshot, String> {
    let files = collect_delta_tree_files(source)?;
    build_delta_snapshot_from_files(files)
}

fn build_delta_dest_snapshot(dest: &Path) -> Result<DeltaSourceSnapshot, String> {
    let files = collect_delta_dest_tree_files(dest)?;
    build_delta_snapshot_from_files(files)
}

fn build_delta_snapshot_from_files(
    files: Vec<DeltaTreeFile>,
) -> Result<DeltaSourceSnapshot, String> {
    let logical_file_bytes = files.iter().try_fold(0u64, |total, file| {
        let len = u64::try_from(file.bytes.len())
            .map_err(|_| "delta source file length exceeds u64::MAX".to_string())?;
        total
            .checked_add(len)
            .ok_or_else(|| "delta source logical size exceeds u64::MAX".to_string())
    })?;
    let object_bytes = encode_delta_tree_object(&files)?;
    let object_sha256_hex = hex::encode(Sha256::digest(&object_bytes));
    let chunk_payloads = split_delta_tree_object_chunks(&object_bytes)?;

    let mut store = DeltaChunkStore::new();
    let ingest = store
        .ingest_ordered_chunks(chunk_payloads.iter().map(Vec::as_slice))
        .map_err(|err| format!("ingest delta source chunks: {err}"))?;
    let manifest = PersistentChunkManifest::new(
        format!("cli-tree:{object_sha256_hex}"),
        ingest.chunks.clone(),
    )
    .map_err(|err| format!("build delta source manifest: {err}"))?;

    let mut chunks_by_content = BTreeMap::new();
    for (chunk, payload) in ingest.chunks.iter().zip(chunk_payloads) {
        chunks_by_content.insert(chunk.content_id.to_hex(), payload);
    }

    Ok(DeltaSourceSnapshot {
        manifest,
        chunks_by_content,
        object_sha256_hex,
        file_count: files.len(),
        logical_file_bytes,
    })
}

fn split_delta_tree_object_chunks(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let mut chunks = Vec::new();
    let mut rolling = DeltaTreeRollingGear::new();
    let mut chunk_start = 0usize;

    for (index, &byte) in bytes.iter().enumerate() {
        rolling.update(byte);
        let end = index + 1;
        let chunk_len = end - chunk_start;

        if chunk_len < DELTA_TREE_OBJECT_MIN_CHUNK_BYTES {
            continue;
        }

        let should_cut = chunk_len >= DELTA_TREE_OBJECT_MAX_CHUNK_BYTES
            || (rolling.hash() & DELTA_TREE_OBJECT_BOUNDARY_MASK) == 0;

        if should_cut {
            chunks.push(bytes[chunk_start..end].to_vec());
            chunk_start = end;
        }
    }

    if chunk_start < bytes.len() {
        if !chunks.is_empty()
            && bytes.len() - chunk_start < DELTA_TREE_OBJECT_MIN_CHUNK_BYTES
            && chunks.last().is_some_and(|previous| {
                previous.len() + bytes.len() - chunk_start <= DELTA_TREE_OBJECT_MAX_CHUNK_BYTES
            })
        {
            let tail = &bytes[chunk_start..];
            if let Some(previous) = chunks.last_mut() {
                previous.extend_from_slice(tail);
            } else {
                chunks.push(tail.to_vec());
            }
        } else {
            chunks.push(bytes[chunk_start..].to_vec());
        }
    }

    Ok(chunks)
}

struct DeltaTreeRollingGear {
    hash: u64,
    window: [u8; DELTA_TREE_OBJECT_CDC_WINDOW_BYTES],
    cursor: usize,
    filled: usize,
}

impl DeltaTreeRollingGear {
    fn new() -> Self {
        Self {
            hash: 0,
            window: [0; DELTA_TREE_OBJECT_CDC_WINDOW_BYTES],
            cursor: 0,
            filled: 0,
        }
    }

    fn update(&mut self, byte: u8) {
        if self.filled < DELTA_TREE_OBJECT_CDC_WINDOW_BYTES {
            self.hash = self.hash.rotate_left(1) ^ delta_tree_gear_value(byte);
            self.window[self.cursor] = byte;
            self.cursor = (self.cursor + 1) % DELTA_TREE_OBJECT_CDC_WINDOW_BYTES;
            self.filled += 1;
            return;
        }

        let old = self.window[self.cursor];
        self.window[self.cursor] = byte;
        self.cursor = (self.cursor + 1) % DELTA_TREE_OBJECT_CDC_WINDOW_BYTES;
        self.hash = self.hash.rotate_left(1)
            ^ delta_tree_gear_value(byte)
            ^ delta_tree_gear_value(old).rotate_left(DELTA_TREE_OBJECT_CDC_WINDOW_BYTES as u32);
    }

    fn hash(&self) -> u64 {
        self.hash
    }
}

const fn delta_tree_gear_value(byte: u8) -> u64 {
    delta_tree_splitmix64((byte as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
}

const fn delta_tree_splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut mixed = value;
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ (mixed >> 31)
}

fn collect_delta_dest_tree_files(dest: &Path) -> Result<Vec<DeltaTreeFile>, String> {
    let metadata = fs::symlink_metadata(dest)
        .map_err(|err| format!("read metadata {}: {err}", dest.display()))?;
    if !metadata.is_dir() {
        return Err(format!(
            "delta destination is not a directory: {}",
            dest.display()
        ));
    }

    let mut files = Vec::new();
    let mut entries = fs::read_dir(dest)
        .map_err(|err| format!("read directory {}: {err}", dest.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("read directory entry {}: {err}", dest.display()))?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("non-UTF-8 path under {}", dest.display()))?;
        if name == DELTA_STATE_DIR || name.starts_with(DELTA_PACKAGE_PREFIX) {
            continue;
        }
        validate_delta_rel_path(&name)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|err| format!("read metadata {}: {err}", path.display()))?;
        if metadata.is_dir() {
            collect_delta_dir(&path, &name, &mut files)?;
        } else if metadata.is_file() {
            let bytes = fs::read(&path).map_err(|err| format!("read {}: {err}", path.display()))?;
            files.push(DeltaTreeFile {
                rel_path: name,
                bytes,
            });
        }
    }

    Ok(files)
}

fn collect_delta_tree_files(source: &Path) -> Result<Vec<DeltaTreeFile>, String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|err| format!("read metadata {}: {err}", source.display()))?;
    let root_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("delta source has no UTF-8 file name: {}", source.display()))?;
    validate_delta_rel_path(root_name)?;

    let mut files = Vec::new();
    if metadata.is_file() {
        let bytes = fs::read(source).map_err(|err| format!("read {}: {err}", source.display()))?;
        files.push(DeltaTreeFile {
            rel_path: root_name.to_string(),
            bytes,
        });
        return Ok(files);
    }
    if metadata.is_dir() {
        collect_delta_dir(source, root_name, &mut files)?;
        return Ok(files);
    }

    Err(format!(
        "unsupported source type for transparent delta: {}",
        source.display()
    ))
}

fn collect_delta_dir(
    dir: &Path,
    rel_prefix: &str,
    files: &mut Vec<DeltaTreeFile>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(dir)
        .map_err(|err| format!("read directory {}: {err}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("read directory entry {}: {err}", dir.display()))?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("non-UTF-8 path under {}", dir.display()))?;
        if name == DELTA_STATE_DIR || name.starts_with(DELTA_PACKAGE_PREFIX) {
            continue;
        }
        let rel_path = format!("{rel_prefix}/{name}");
        validate_delta_rel_path(&rel_path)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|err| format!("read metadata {}: {err}", path.display()))?;
        if metadata.is_dir() {
            collect_delta_dir(&path, &rel_path, files)?;
        } else if metadata.is_file() {
            let bytes = fs::read(&path).map_err(|err| format!("read {}: {err}", path.display()))?;
            files.push(DeltaTreeFile { rel_path, bytes });
        } else {
            return Err(format!(
                "unsupported source type for transparent delta: {}",
                path.display()
            ));
        }
    }

    Ok(())
}

fn encode_delta_tree_object(files: &[DeltaTreeFile]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut payloads = BTreeMap::<([u8; 32], u64), &[u8]>::new();

    out.extend_from_slice(DELTA_TREE_OBJECT_MAGIC);
    put_u64(&mut out, files.len() as u64);
    for file in files {
        let payload_len = u64::try_from(file.bytes.len())
            .map_err(|_| "delta file length exceeds u64::MAX".to_string())?;
        let payload_sha256 = sha256_array(&file.bytes);
        put_len_prefixed(&mut out, file.rel_path.as_bytes())?;
        put_u64(&mut out, payload_len);
        out.extend_from_slice(&payload_sha256);
        payloads
            .entry((payload_sha256, payload_len))
            .or_insert_with(|| file.bytes.as_slice());
    }

    put_u64(&mut out, payloads.len() as u64);
    for ((payload_sha256, payload_len), payload) in payloads {
        out.extend_from_slice(&payload_sha256);
        put_u64(&mut out, payload_len);
        out.extend_from_slice(payload);
    }
    Ok(out)
}

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn put_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| "delta length-prefixed field exceeds u32::MAX".to_string())?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn validate_delta_rel_path(rel_path: &str) -> Result<(), String> {
    if rel_path.is_empty()
        || rel_path.starts_with('/')
        || rel_path.contains('\\')
        || rel_path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part == DELTA_STATE_DIR)
    {
        return Err(format!("unsafe delta relative path: {rel_path}"));
    }
    Ok(())
}

fn unique_micros() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
}

fn handle_post_receive_delta(dest: &Path, enabled: bool) -> Result<(), String> {
    if !enabled {
        return Ok(());
    }
    let applied = apply_delta_packages(dest)?;
    if applied == 0 && !dest.is_dir() {
        return Ok(());
    }
    refresh_delta_state(dest).map(|_| ())
}

fn apply_delta_packages(dest: &Path) -> Result<usize, String> {
    if !dest.is_dir() {
        return Ok(0);
    }
    let mut packages = fs::read_dir(dest)
        .map_err(|err| format!("read destination {}: {err}", dest.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("read destination entry {}: {err}", dest.display()))?;
    packages.sort_by_key(|entry| entry.file_name());

    let mut applied = 0usize;
    for entry in packages {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("non-UTF-8 path under {}", dest.display()))?;
        if !name.starts_with(DELTA_PACKAGE_PREFIX) {
            continue;
        }
        let path = entry.path();
        if path.is_dir() && !path.join(".applied").exists() {
            apply_delta_package(dest, &path)?;
            let receipt = path.join(".applied");
            fs::write(&receipt, unique_micros().to_string()).map_err(|err| {
                format!("write delta package receipt {}: {err}", receipt.display())
            })?;
            applied += 1;
        }
    }
    Ok(applied)
}

fn apply_delta_package(dest: &Path, package_root: &Path) -> Result<(), String> {
    let metadata_path = package_root.join(DELTA_PACKAGE_FILE);
    let metadata_bytes = fs::read(&metadata_path)
        .map_err(|err| format!("read delta package {}: {err}", metadata_path.display()))?;
    let metadata: DeltaPackageMetadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|err| format!("parse delta package {}: {err}", metadata_path.display()))?;
    if metadata.schema != DELTA_PACKAGE_SCHEMA {
        return Err(format!(
            "unsupported delta package schema {} in {}",
            metadata.schema,
            metadata_path.display()
        ));
    }

    let target_manifest = decode_delta_package_target_manifest(&metadata)?;

    let receiver_state = read_local_delta_state(dest)?.ok_or_else(|| {
        "delta package received but receiver has no prior delta state".to_string()
    })?;
    let receiver_manifest = receiver_state.manifest()?;
    let mut store = load_delta_store_from_state(dest, &receiver_manifest)?;

    let chunk_dir = package_root.join(DELTA_CHUNK_DIR);
    for chunk in &metadata.missing_chunks {
        validate_hex_hash(&chunk.content_id_hex)?;
        let path = chunk_dir.join(&chunk.file_name);
        let bytes = fs::read(&path)
            .map_err(|err| format!("read delta package chunk {}: {err}", path.display()))?;
        let len = u64::try_from(bytes.len()).map_err(|_| {
            format!(
                "delta package chunk {} length exceeds u64::MAX",
                path.display()
            )
        })?;
        if len != chunk.size_bytes {
            return Err(format!(
                "delta package chunk {} size mismatch: expected {}, got {}",
                path.display(),
                chunk.size_bytes,
                len
            ));
        }
        let content_id = ContentId::from_bytes(&bytes);
        if content_id.to_hex() != chunk.content_id_hex {
            return Err(format!(
                "delta package chunk {} content id mismatch",
                path.display()
            ));
        }
        store
            .insert(&bytes)
            .map_err(|err| format!("insert delta package chunk: {err}"))?;
    }

    let subchunk_dir = package_root.join(DELTA_SUBCHUNK_DIR);
    for subdelta in &metadata.subdelta_chunks {
        validate_hex_hash(&subdelta.target_content_id_hex)?;
        let target_sha256 = decode_sha256_hex(
            &subdelta.target_sha256_hex,
            "delta package sub-delta target sha256",
        )?;
        validate_hex_hash(&subdelta.base_content_id_hex)?;
        let target_chunk = target_manifest
            .chunks
            .iter()
            .find(|chunk| chunk.content_id.to_hex() == subdelta.target_content_id_hex)
            .ok_or_else(|| {
                format!(
                    "delta package sub-delta target {} not present in target manifest",
                    subdelta.target_content_id_hex
                )
            })?;
        if target_chunk.size_bytes != subdelta.target_size_bytes {
            return Err(format!(
                "delta package sub-delta target {} size mismatch: expected {}, metadata {}",
                subdelta.target_content_id_hex, target_chunk.size_bytes, subdelta.target_size_bytes
            ));
        }
        let base_chunk = receiver_manifest
            .chunks
            .iter()
            .find(|chunk| chunk.content_id.to_hex() == subdelta.base_content_id_hex)
            .ok_or_else(|| {
                format!(
                    "delta package sub-delta base {} not present in receiver manifest",
                    subdelta.base_content_id_hex
                )
            })?;
        if base_chunk.size_bytes != subdelta.base_size_bytes {
            return Err(format!(
                "delta package sub-delta base {} size mismatch: expected {}, metadata {}",
                subdelta.base_content_id_hex, base_chunk.size_bytes, subdelta.base_size_bytes
            ));
        }
        let old_bytes = store.get(&base_chunk.content_id).ok_or_else(|| {
            format!(
                "receiver state missing base chunk {}",
                subdelta.base_content_id_hex
            )
        })?;
        let ops_path = subchunk_dir.join(&subdelta.ops_file_name);
        let encoded_ops = fs::read(&ops_path).map_err(|err| {
            format!(
                "read delta package sub-delta ops {}: {err}",
                ops_path.display()
            )
        })?;
        let encoded_len = u64::try_from(encoded_ops.len())
            .map_err(|_| "delta package sub-delta ops length exceeds u64::MAX".to_string())?;
        if encoded_len != subdelta.ops_wire_bytes {
            return Err(format!(
                "delta package sub-delta ops {} size mismatch: expected {}, got {}",
                subdelta.ops_file_name, subdelta.ops_wire_bytes, encoded_len
            ));
        }
        let ops = decode_subdelta_ops(&encoded_ops)
            .map_err(|err| format!("parse delta package sub-delta ops: {err}"))?;
        let rebuilt = delta_subchunk::reconstruct_verified(old_bytes, &ops, &target_sha256)
            .map_err(|err| format!("reconstruct delta package sub-delta: {err}"))?;
        let rebuilt_len = u64::try_from(rebuilt.len())
            .map_err(|_| "delta package reconstructed chunk length exceeds u64::MAX".to_string())?;
        if rebuilt_len != target_chunk.size_bytes {
            return Err(format!(
                "delta package reconstructed chunk {} size mismatch: expected {}, got {}",
                subdelta.target_content_id_hex, target_chunk.size_bytes, rebuilt_len
            ));
        }
        store
            .insert(&rebuilt)
            .map_err(|err| format!("insert delta package reconstructed chunk: {err}"))?;
    }

    for repeated in &metadata.repeated_chunks {
        validate_hex_hash(&repeated.target_content_id_hex)?;
        let target_chunk = target_manifest
            .chunks
            .iter()
            .find(|chunk| chunk.content_id.to_hex() == repeated.target_content_id_hex)
            .ok_or_else(|| {
                format!(
                    "delta package repeated target {} not present in target manifest",
                    repeated.target_content_id_hex
                )
            })?;
        if target_chunk.size_bytes != repeated.target_size_bytes {
            return Err(format!(
                "delta package repeated target {} size mismatch: expected {}, metadata {}",
                repeated.target_content_id_hex, target_chunk.size_bytes, repeated.target_size_bytes
            ));
        }
        if store.get(&target_chunk.content_id).is_none() {
            return Err(format!(
                "delta package repeated target {} missing carried payload",
                repeated.target_content_id_hex
            ));
        }
    }

    target_manifest
        .verify_store_coverage(&store)
        .map_err(|err| format!("delta package target coverage failed: {err}"))?;
    let object_bytes = reconstruct_delta_object_bytes(&target_manifest, &store)?;
    let object_sha256_hex = hex::encode(Sha256::digest(&object_bytes));
    if object_sha256_hex != metadata.object_sha256_hex {
        return Err(format!(
            "delta package object sha256 mismatch: expected {}, got {}",
            metadata.object_sha256_hex, object_sha256_hex
        ));
    }
    let files = decode_delta_tree_object(&object_bytes)?;
    commit_delta_tree_files(dest, &files, &object_sha256_hex)
}

fn refresh_delta_state(dest: &Path) -> Result<DeltaCliState, String> {
    let snapshot = build_delta_dest_snapshot(dest)?;
    let state_dir = dest.join(DELTA_STATE_DIR);
    let chunk_dir = state_dir.join(DELTA_CHUNK_DIR);
    fs::create_dir_all(&chunk_dir)
        .map_err(|err| format!("create delta state dir {}: {err}", chunk_dir.display()))?;

    for (content_id_hex, payload) in &snapshot.chunks_by_content {
        validate_hex_hash(content_id_hex)?;
        let path = chunk_dir.join(format!("{content_id_hex}.chunk"));
        if !path.exists() {
            let mut file = fs::File::create(&path)
                .map_err(|err| format!("create delta state chunk {}: {err}", path.display()))?;
            file.write_all(payload)
                .map_err(|err| format!("write delta state chunk {}: {err}", path.display()))?;
        }
    }

    let state = delta_cli_state_from_snapshot(&snapshot)?;
    let path = state_dir.join(DELTA_STATE_FILE);
    let mut file = fs::File::create(&path)
        .map_err(|err| format!("create delta state {}: {err}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, &state)
        .map_err(|err| format!("write delta state {}: {err}", path.display()))?;
    file.write_all(b"\n")
        .map_err(|err| format!("finish delta state {}: {err}", path.display()))?;
    Ok(state)
}

fn delta_cli_state_from_snapshot(snapshot: &DeltaSourceSnapshot) -> Result<DeltaCliState, String> {
    for chunk in &snapshot.manifest.chunks {
        let content_id_hex = chunk.content_id.to_hex();
        let payload = snapshot
            .chunks_by_content
            .get(&content_id_hex)
            .ok_or_else(|| format!("delta state source missing chunk {content_id_hex}"))?;
        let payload_len = u64::try_from(payload.len())
            .map_err(|_| "delta state chunk payload length exceeds u64::MAX".to_string())?;
        if payload_len != chunk.size_bytes || ContentId::from_bytes(payload) != chunk.content_id {
            return Err(format!(
                "delta state source chunk {content_id_hex} does not match manifest"
            ));
        }
    }

    Ok(DeltaCliState {
        schema: DELTA_STATE_SCHEMA.to_string(),
        manifest_hex: hex::encode(snapshot.manifest.to_canonical_bytes()),
        object_sha256_hex: snapshot.object_sha256_hex.clone(),
        chunk_count: snapshot.chunks_by_content.len(),
        logical_file_bytes: snapshot.logical_file_bytes,
        chunk_signatures: Vec::new(),
    })
}

fn read_local_delta_state(dest: &Path) -> Result<Option<DeltaCliState>, String> {
    let path = dest.join(DELTA_STATE_DIR).join(DELTA_STATE_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        fs::read(&path).map_err(|err| format!("read delta state {}: {err}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|err| format!("parse delta state {}: {err}", path.display()))
}

fn delta_state_addr(base: SocketAddr) -> Option<SocketAddr> {
    let port = base.port().checked_add(1)?;
    Some(SocketAddr::new(base.ip(), port))
}

struct DeltaStateServerGuard {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for DeltaStateServerGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn spawn_delta_state_server(
    dest: PathBuf,
    listen: SocketAddr,
    enabled: bool,
) -> Option<DeltaStateServerGuard> {
    if !enabled || listen.port() == 0 {
        return None;
    }
    let state_addr = delta_state_addr(listen)?;
    let listener = match std::net::TcpListener::bind(state_addr) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("atp: delta state sidecar disabled on {state_addr}: bind failed: {err}");
            return None;
        }
    };
    if let Err(err) = listener.set_nonblocking(true) {
        eprintln!("atp: delta state sidecar disabled on {state_addr}: nonblocking failed: {err}");
        return None;
    }

    eprintln!("atp: delta state sidecar listening on {state_addr}");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !stop_for_thread.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _peer)) => serve_delta_state_connection(stream, &dest),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(err) => {
                    eprintln!("atp: delta state sidecar accept failed: {err}");
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    });
    Some(DeltaStateServerGuard {
        stop,
        handle: Some(handle),
    })
}

fn serve_delta_state_connection(mut stream: std::net::TcpStream, dest: &Path) {
    match read_delta_state_sidecar_request(&mut stream) {
        Ok(Some(body)) => {
            if let Err(err) = serve_delta_subchunk_signature_request(&mut stream, dest, &body) {
                eprintln!("atp: delta state sidecar signature request failed: {err}");
            }
            return;
        }
        Ok(None) => {}
        Err(err) => {
            eprintln!("atp: delta state sidecar request read failed: {err}");
            return;
        }
    }

    match read_local_delta_state(dest) {
        Ok(Some(state)) => {
            if let Err(err) = serde_json::to_writer(&mut stream, &state) {
                eprintln!("atp: delta state sidecar write failed: {err}");
                return;
            }
            if let Err(err) = stream.write_all(b"\n").and_then(|_| stream.flush()) {
                eprintln!("atp: delta state sidecar finish failed: {err}");
            }
        }
        Ok(None) => {}
        Err(err) => eprintln!("atp: delta state sidecar could not read state: {err}"),
    }
}

fn read_delta_state_sidecar_request(
    stream: &mut std::net::TcpStream,
) -> std::io::Result<Option<String>> {
    stream.set_read_timeout(Some(Duration::from_millis(50)))?;
    let mut body = String::new();
    match stream.read_to_string(&mut body) {
        Ok(_) => {
            let trimmed = body.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn serve_delta_subchunk_signature_request(
    stream: &mut std::net::TcpStream,
    dest: &Path,
    body: &str,
) -> Result<(), String> {
    let request: DeltaSubchunkSignatureRequest = serde_json::from_str(body)
        .map_err(|err| format!("parse subchunk signature request: {err}"))?;
    let response = build_delta_subchunk_signature_response(dest, request)?;
    serde_json::to_writer(&mut *stream, &response)
        .map_err(|err| format!("write subchunk signature response: {err}"))?;
    stream
        .write_all(b"\n")
        .and_then(|_| stream.flush())
        .map_err(|err| format!("finish subchunk signature response: {err}"))
}

fn build_delta_subchunk_signature_response(
    dest: &Path,
    request: DeltaSubchunkSignatureRequest,
) -> Result<DeltaSubchunkSignatureResponse, String> {
    if request.schema != DELTA_SUBCHUNK_SIGNATURE_REQUEST_SCHEMA {
        return Err(format!(
            "unsupported subchunk signature request schema: {}",
            request.schema
        ));
    }
    let receiver_state = read_local_delta_state(dest)?.ok_or_else(|| {
        "subchunk signature request received but receiver has no delta state".to_string()
    })?;
    let receiver_manifest = receiver_state.manifest()?;
    let store = load_delta_store_from_state(dest, &receiver_manifest)?;

    let mut signatures = Vec::new();
    for requested in request.chunks {
        validate_hex_hash(&requested.content_id_hex)?;
        let Some(chunk) = receiver_manifest.chunks.iter().find(|chunk| {
            chunk.content_id.to_hex() == requested.content_id_hex
                && chunk.size_bytes == requested.size_bytes
        }) else {
            continue;
        };
        let Some(payload) = store.get(&chunk.content_id) else {
            continue;
        };
        let payload_len = u64::try_from(payload.len())
            .map_err(|_| "delta state chunk payload length exceeds u64::MAX".to_string())?;
        if payload_len != chunk.size_bytes || ContentId::from_bytes(payload) != chunk.content_id {
            return Err(format!(
                "delta state source chunk {} does not match manifest",
                requested.content_id_hex
            ));
        }
        signatures.push(DeltaChunkSignatureState {
            content_id_hex: requested.content_id_hex,
            size_bytes: requested.size_bytes,
            signature: delta_subchunk::signature(payload, delta_subchunk::DEFAULT_SUBBLOCK_BYTES),
        });
    }

    Ok(DeltaSubchunkSignatureResponse {
        schema: DELTA_SUBCHUNK_SIGNATURE_RESPONSE_SCHEMA.to_string(),
        signatures,
    })
}

fn load_delta_store_from_state(
    dest: &Path,
    manifest: &PersistentChunkManifest,
) -> Result<DeltaChunkStore, String> {
    let chunk_dir = dest.join(DELTA_STATE_DIR).join(DELTA_CHUNK_DIR);
    let mut store = DeltaChunkStore::new();
    let mut loaded = BTreeMap::<String, ()>::new();
    for chunk in &manifest.chunks {
        let content_id_hex = chunk.content_id.to_hex();
        if loaded.insert(content_id_hex.clone(), ()).is_some() {
            continue;
        }
        let path = chunk_dir.join(format!("{content_id_hex}.chunk"));
        let mut file = fs::File::open(&path)
            .map_err(|err| format!("open delta state chunk {}: {err}", path.display()))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|err| format!("read delta state chunk {}: {err}", path.display()))?;
        let len = u64::try_from(bytes.len()).map_err(|_| {
            format!(
                "delta state chunk {} length exceeds u64::MAX",
                path.display()
            )
        })?;
        if len != chunk.size_bytes || ContentId::from_bytes(&bytes) != chunk.content_id {
            return Err(format!(
                "delta state chunk {} does not match manifest",
                path.display()
            ));
        }
        store
            .insert(&bytes)
            .map_err(|err| format!("insert delta state chunk: {err}"))?;
    }
    Ok(store)
}

fn reconstruct_delta_object_bytes(
    manifest: &PersistentChunkManifest,
    store: &DeltaChunkStore,
) -> Result<Vec<u8>, String> {
    let capacity = usize::try_from(manifest.total_size_bytes)
        .map_err(|_| "delta object exceeds addressable memory on this host".to_string())?;
    let mut bytes = Vec::with_capacity(capacity);
    for chunk in &manifest.chunks {
        let payload = store.get(&chunk.content_id).ok_or_else(|| {
            format!(
                "delta store missing target chunk {}",
                chunk.content_id.to_hex()
            )
        })?;
        let payload_len = u64::try_from(payload.len())
            .map_err(|_| "delta chunk length exceeds u64::MAX".to_string())?;
        if payload_len != chunk.size_bytes || ContentId::from_bytes(payload) != chunk.content_id {
            return Err(format!(
                "delta store chunk {} failed final verification",
                chunk.content_id.to_hex()
            ));
        }
        bytes.extend_from_slice(payload);
    }
    Ok(bytes)
}

fn decode_delta_tree_object(bytes: &[u8]) -> Result<Vec<DeltaTreeFile>, String> {
    let mut reader = DeltaObjectReader::new(bytes);
    reader.expect_magic(DELTA_TREE_OBJECT_MAGIC)?;
    let file_count = reader.read_u64()?;
    let file_count = usize::try_from(file_count)
        .map_err(|_| "delta object file count exceeds usize::MAX".to_string())?;
    let mut entries = Vec::with_capacity(file_count);
    for _ in 0..file_count {
        let rel_path = reader.read_string()?;
        validate_delta_rel_path(&rel_path)?;
        let len = reader.read_u64()?;
        let payload_sha256 = reader.read_sha256()?;
        entries.push((rel_path, len, payload_sha256));
    }

    let payload_count = reader.read_u64()?;
    let payload_count = usize::try_from(payload_count)
        .map_err(|_| "delta object payload count exceeds usize::MAX".to_string())?;
    let mut payloads = BTreeMap::<([u8; 32], u64), Vec<u8>>::new();
    for _ in 0..payload_count {
        let payload_sha256 = reader.read_sha256()?;
        let payload_len = reader.read_u64()?;
        let len = usize::try_from(payload_len)
            .map_err(|_| "delta object payload length exceeds usize::MAX".to_string())?;
        let payload = reader.read_exact(len)?.to_vec();
        let observed_sha256 = sha256_array(&payload);
        if observed_sha256 != payload_sha256 {
            return Err("delta object payload sha256 mismatch".to_string());
        }
        if payloads
            .insert((payload_sha256, payload_len), payload)
            .is_some()
        {
            return Err("delta object contains duplicate payload entry".to_string());
        }
    }

    let mut files = Vec::with_capacity(file_count);
    for (rel_path, len, payload_sha256) in entries {
        let payload = payloads.get(&(payload_sha256, len)).ok_or_else(|| {
            format!(
                "delta object missing payload {}:{} for {rel_path}",
                hex::encode(payload_sha256),
                len
            )
        })?;
        files.push(DeltaTreeFile {
            rel_path,
            bytes: payload.clone(),
        });
    }
    reader.expect_eof()?;
    Ok(files)
}

fn commit_delta_tree_files(
    dest: &Path,
    files: &[DeltaTreeFile],
    object_sha256_hex: &str,
) -> Result<(), String> {
    let root_name = delta_tree_root_name(files)?;
    let state_dir = dest.join(DELTA_STATE_DIR);
    let staging_root = state_dir.join(format!("staging-{object_sha256_hex}"));
    if staging_root.exists() {
        return Err(format!(
            "delta staging root already exists: {}",
            staging_root.display()
        ));
    }
    fs::create_dir_all(&staging_root).map_err(|err| {
        format!(
            "create delta staging root {}: {err}",
            staging_root.display()
        )
    })?;
    write_delta_files_under(&staging_root, files)?;

    let staged_target = staging_root.join(&root_name);
    let final_target = dest.join(&root_name);
    let backup = if final_target.exists() {
        let backup_dir = state_dir.join("backups");
        fs::create_dir_all(&backup_dir)
            .map_err(|err| format!("create delta backup dir {}: {err}", backup_dir.display()))?;
        let backup = backup_dir.join(format!(
            "{}-{}",
            sanitize_backup_name(&root_name),
            unique_micros()
        ));
        fs::rename(&final_target, &backup).map_err(|err| {
            format!(
                "move existing target {} to backup {}: {err}",
                final_target.display(),
                backup.display()
            )
        })?;
        Some(backup)
    } else {
        None
    };

    match fs::rename(&staged_target, &final_target) {
        Ok(()) => Ok(()),
        Err(err) => {
            if let Some(backup) = backup {
                let _ = fs::rename(&backup, &final_target);
            }
            Err(format!(
                "commit delta target {} from staging {}: {err}",
                final_target.display(),
                staged_target.display()
            ))
        }
    }
}

fn write_delta_files_under(root: &Path, files: &[DeltaTreeFile]) -> Result<(), String> {
    for file in files {
        let rel = safe_delta_path(&file.rel_path)?;
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("create delta output dir {}: {err}", parent.display()))?;
        }
        let mut output = fs::File::create(&path)
            .map_err(|err| format!("create delta output file {}: {err}", path.display()))?;
        output
            .write_all(&file.bytes)
            .map_err(|err| format!("write delta output file {}: {err}", path.display()))?;
    }
    Ok(())
}

fn delta_tree_root_name(files: &[DeltaTreeFile]) -> Result<String, String> {
    let mut root: Option<&str> = None;
    for file in files {
        let candidate = file
            .rel_path
            .split('/')
            .next()
            .ok_or_else(|| format!("unsafe delta relative path: {}", file.rel_path))?;
        match root {
            Some(existing) if existing != candidate => {
                return Err(format!(
                    "delta object spans multiple top-level roots: {existing} and {candidate}"
                ));
            }
            None => root = Some(candidate),
            _ => {}
        }
    }
    root.map(ToOwned::to_owned)
        .ok_or_else(|| "delta object contains no files".to_string())
}

fn safe_delta_path(rel_path: &str) -> Result<PathBuf, String> {
    validate_delta_rel_path(rel_path)?;
    let mut path = PathBuf::new();
    for component in rel_path.split('/') {
        path.push(component);
    }
    Ok(path)
}

fn sanitize_backup_name(root_name: &str) -> String {
    root_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn validate_hex_hash(value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!("expected 64-character hex hash, got {value:?}"))
    }
}

fn decode_sha256_hex(value: &str, label: &str) -> Result<[u8; 32], String> {
    validate_hex_hash(value)?;
    let bytes = hex::decode(value).map_err(|err| format!("decode {label}: {err}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} did not decode to 32 bytes"))
}

struct DeltaObjectReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> DeltaObjectReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn expect_magic(&mut self, magic: &[u8]) -> Result<(), String> {
        let observed = self.read_exact(magic.len())?;
        if observed == magic {
            Ok(())
        } else {
            Err("delta object has invalid magic".to_string())
        }
    }

    fn read_string(&mut self) -> Result<String, String> {
        let len = self.read_u32()?;
        let len = usize::try_from(len)
            .map_err(|_| "delta object string length exceeds usize::MAX".to_string())?;
        let bytes = self.read_exact(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| "delta object string is not valid UTF-8".to_string())
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| "delta object ended mid-u32".to_string())?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| "delta object ended mid-u64".to_string())?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_sha256(&mut self) -> Result<[u8; 32], String> {
        self.read_exact(32)?
            .try_into()
            .map_err(|_| "delta object ended mid-sha256".to_string())
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or_else(|| "delta object cursor overflow".to_string())?;
        let slice = self
            .bytes
            .get(self.cursor..end)
            .ok_or_else(|| "delta object is truncated".to_string())?;
        self.cursor = end;
        Ok(slice)
    }

    fn expect_eof(&self) -> Result<(), String> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err("delta object has trailing bytes".to_string())
        }
    }
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
        args.max_block_size.remote_arg(),
        "--repair-overhead".to_string(),
        args.repair_overhead.to_string(),
        "--rq-round0-loss-pct".to_string(),
        args.rq_round0_loss_pct.to_string(),
        "--rq-tail-drain-ms".to_string(),
        args.rq_tail_drain_ms.to_string(),
    ];
    if matches!(rq_auth, Some(RqAuthChoice::UnauthenticatedLab)) {
        argv.push("--rq-allow-unauthenticated-lab".to_string());
    }
    if args.no_delta {
        argv.push("--no-delta".to_string());
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

#[cfg(any())]
mod unused_delta_sidecar_draft {
    use super::*;

    #[derive(Debug)]
    enum DeltaSshSend {
        AlreadyInSync(serde_json::Value),
        Package {
            package_root: PathBuf,
            plan: DeltaResyncPlan,
        },
    }

    #[cfg(any())]
    mod unused_cli_delta_package_v2 {
        use super::*;

        #[derive(Debug)]
        struct DeltaMaterial {
            root_name: String,
            is_directory: bool,
            entries: Vec<DeltaPackageEntry>,
            manifest: PersistentChunkManifest,
            store: DeltaChunkStore,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct DeltaPackageEntry {
            rel_path: String,
            size_bytes: u64,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct DeltaPackageChunk {
            index: u32,
            content_id_hex: String,
            size_bytes: u64,
            file_name: String,
        }

        #[derive(Debug, Serialize, Deserialize)]
        struct DeltaPackage {
            schema: String,
            target_root_name: String,
            target_is_directory: bool,
            target_manifest_hex: String,
            entries: Vec<DeltaPackageEntry>,
            chunks: Vec<DeltaPackageChunk>,
        }

        #[derive(Debug, Serialize, Deserialize)]
        struct DeltaState {
            schema: String,
            root_name: String,
            is_directory: bool,
            manifest_hex: String,
            updated_unix_secs: u64,
        }

        fn prepare_delta_ssh_send(
            args: &SendArgs,
            remote: &RemoteTarget,
        ) -> Result<Option<DeltaSshSend>, String> {
            let source = build_delta_material_from_path(&args.source)?;
            let Some(state) = read_remote_delta_state(args, remote)? else {
                return Ok(None);
            };
            if state.schema != DELTA_STATE_SCHEMA
                || state.root_name != source.root_name
                || state.is_directory != source.is_directory
            {
                return Ok(None);
            }

            let receiver_manifest = PersistentChunkManifest::from_canonical_bytes(&decode_hex(
                &state.manifest_hex,
                "remote delta manifest",
            )?)
            .map_err(|err| format!("decode remote delta manifest: {err}"))?;
            let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver_manifest);
            let plan = plan_incremental_resync_with_receiver_coverage(
                &source.manifest,
                Some(&receiver_manifest),
                &receiver_coverage,
            );

            match plan.mode {
                DeltaResyncMode::AlreadyInSync => {
                    Ok(Some(DeltaSshSend::AlreadyInSync(serde_json::json!({
                        "event": "atp_send",
                        "transport": args.transport.cli_arg(),
                        "delta_mode": "already_in_sync",
                        "committed": true,
                        "bytes_sent": 0,
                        "files": source.entries.len(),
                        "merkle_root": source.manifest.merkle_root.to_hex(),
                        "peer": remote.ssh_host,
                    }))))
                }
                DeltaResyncMode::DeltaChunks => {
                    let package_root = write_delta_package(&source, &plan)?;
                    Ok(Some(DeltaSshSend::Package { package_root, plan }))
                }
                DeltaResyncMode::FullObjectFallback => Ok(None),
            }
        }

        fn read_remote_delta_state(
            args: &SendArgs,
            remote: &RemoteTarget,
        ) -> Result<Option<DeltaState>, String> {
            let state_path = Path::new(&remote.remote_path)
                .join(DELTA_STATE_DIR)
                .join(DELTA_STATE_FILE);
            let mut command = ssh_command(args, &remote.ssh_host);
            command.arg(format!(
                "cat {}",
                shell_quote(&state_path.display().to_string())
            ));
            let output = command
                .output()
                .map_err(|err| format!("read remote delta state: {err}"))?;
            if !output.status.success() {
                return Ok(None);
            }
            serde_json::from_slice(&output.stdout)
                .map(Some)
                .map_err(|err| format!("parse remote delta state: {err}"))
        }

        fn build_delta_material_from_path(root: &Path) -> Result<DeltaMaterial, String> {
            let root_name = root.file_name().map_or_else(
                || "transfer".to_string(),
                |name| name.to_string_lossy().into_owned(),
            );
            let metadata = fs::metadata(root)
                .map_err(|err| format!("stat delta source {}: {err}", root.display()))?;
            let is_directory = metadata.is_dir();
            let mut files = Vec::new();
            if metadata.is_file() {
                files.push((root_name.clone(), root.to_path_buf()));
            } else if is_directory {
                collect_delta_files(root, root, &mut files)?;
            } else {
                return Err(format!(
                    "delta source {} is not a regular file or directory",
                    root.display()
                ));
            }
            files.sort_by(|left, right| left.0.cmp(&right.0));

            let mut store = DeltaChunkStore::new();
            let mut chunks = Vec::new();
            let mut entries = Vec::new();
            let mut stream_offset = 0u64;
            for (rel_path, path) in files {
                let mut file = fs::File::open(&path)
                    .map_err(|err| format!("open delta source {}: {err}", path.display()))?;
                let mut entry_size = 0u64;
                let mut buf = vec![0u8; DELTA_TREE_OBJECT_MAX_CHUNK_BYTES];
                loop {
                    let n = file
                        .read(&mut buf)
                        .map_err(|err| format!("read delta source {}: {err}", path.display()))?;
                    if n == 0 {
                        break;
                    }
                    let insert = store
                        .insert(&buf[..n])
                        .map_err(|err| format!("store delta chunk: {err}"))?;
                    let index = u32::try_from(chunks.len())
                        .map_err(|_| "delta manifest chunk count exceeds u32::MAX".to_string())?;
                    let size_bytes = u64::try_from(n)
                        .map_err(|_| "delta chunk length exceeds u64::MAX".to_string())?;
                    chunks.push(CasChunkRef {
                        index,
                        byte_offset: stream_offset,
                        size_bytes,
                        content_id: insert.content_id,
                    });
                    entry_size = entry_size.saturating_add(size_bytes);
                    stream_offset = stream_offset.saturating_add(size_bytes);
                }
                entries.push(DeltaPackageEntry {
                    rel_path,
                    size_bytes: entry_size,
                });
            }

            let manifest = PersistentChunkManifest::new(root_name.clone(), chunks)
                .map_err(|err| format!("build delta manifest: {err}"))?;
            Ok(DeltaMaterial {
                root_name,
                is_directory,
                entries,
                manifest,
                store,
            })
        }

        fn collect_delta_files(
            root: &Path,
            dir: &Path,
            files: &mut Vec<(String, PathBuf)>,
        ) -> Result<(), String> {
            let mut entries = fs::read_dir(dir)
                .map_err(|err| format!("read delta directory {}: {err}", dir.display()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| format!("read delta directory entry: {err}"))?;
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let file_type = entry
                    .file_type()
                    .map_err(|err| format!("stat delta entry {}: {err}", path.display()))?;
                if file_type.is_dir() {
                    collect_delta_files(root, &path, files)?;
                } else if file_type.is_file() {
                    let rel_path = path
                        .strip_prefix(root)
                        .map_err(|err| format!("strip delta root {}: {err}", path.display()))?
                        .components()
                        .map(|component| component.as_os_str().to_string_lossy())
                        .collect::<Vec<_>>()
                        .join("/");
                    files.push((rel_path, path));
                }
            }
            Ok(())
        }

        fn write_delta_package(
            source: &DeltaMaterial,
            plan: &DeltaResyncPlan,
        ) -> Result<PathBuf, String> {
            let package_root = env::temp_dir().join(format!(
                "{DELTA_PACKAGE_PREFIX}{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|err| format!("system clock before unix epoch: {err}"))?
                    .as_nanos()
            ));
            let chunk_dir = package_root.join(DELTA_CHUNK_DIR);
            fs::create_dir_all(&chunk_dir)
                .map_err(|err| format!("create delta package {}: {err}", chunk_dir.display()))?;

            let mut chunk_records = Vec::new();
            for chunk in &plan.missing_chunks {
                let bytes = source.store.get(&chunk.content_id).ok_or_else(|| {
                    format!("delta chunk {} missing from sender CAS", chunk.content_id)
                })?;
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != chunk.size_bytes {
                    return Err(format!(
                        "delta chunk {} size mismatch before packaging",
                        chunk.content_id
                    ));
                }
                let file_name = delta_chunk_file_name(&chunk.content_id, chunk.size_bytes);
                let path = chunk_dir.join(&file_name);
                fs::File::create(&path)
                    .and_then(|mut file| file.write_all(bytes))
                    .map_err(|err| format!("write delta chunk {}: {err}", path.display()))?;
                chunk_records.push(DeltaPackageChunk {
                    index: chunk.index,
                    content_id_hex: chunk.content_id.to_hex(),
                    size_bytes: chunk.size_bytes,
                    file_name,
                });
            }

            let package = DeltaPackage {
                schema: DELTA_PACKAGE_SCHEMA.to_string(),
                target_root_name: source.root_name.clone(),
                target_is_directory: source.is_directory,
                target_manifest_hex: hex::encode(source.manifest.to_canonical_bytes()),
                entries: source.entries.clone(),
                chunks: chunk_records,
            };
            let package_json = serde_json::to_vec_pretty(&package)
                .map_err(|err| format!("encode delta package: {err}"))?;
            fs::write(package_root.join(DELTA_PACKAGE_FILE), package_json)
                .map_err(|err| format!("write delta package manifest: {err}"))?;
            Ok(package_root)
        }

        fn maybe_apply_delta_after_receive(
            dest: &Path,
            report: &ReceiveReport,
        ) -> Result<(), String> {
            for path in &report.committed_paths {
                if path
                    .file_name()
                    .is_some_and(|name| name == DELTA_PACKAGE_FILE)
                {
                    apply_delta_package(dest, path)?;
                    return Ok(());
                }
            }
            refresh_delta_state_from_report(dest, report)
        }

        fn apply_delta_package(dest: &Path, package_manifest_path: &Path) -> Result<(), String> {
            let package_root = package_manifest_path
                .parent()
                .ok_or_else(|| "delta package manifest has no parent directory".to_string())?;
            let package: DeltaPackage = serde_json::from_slice(
                &fs::read(package_manifest_path)
                    .map_err(|err| format!("read delta package manifest: {err}"))?,
            )
            .map_err(|err| format!("parse delta package manifest: {err}"))?;
            if package.schema != DELTA_PACKAGE_SCHEMA {
                return Err(format!(
                    "unsupported delta package schema: {}",
                    package.schema
                ));
            }

            let target_manifest = PersistentChunkManifest::from_canonical_bytes(&decode_hex(
                &package.target_manifest_hex,
                "delta package target manifest",
            )?)
            .map_err(|err| format!("decode delta package target manifest: {err}"))?;

            let target_root = dest.join(&package.target_root_name);
            let prior_store = if target_root.exists() {
                build_delta_material_from_path(&target_root)
                    .map(|material| material.store)
                    .unwrap_or_else(|_| DeltaChunkStore::new())
            } else {
                DeltaChunkStore::new()
            };
            let mut decoded = BTreeMap::<ContentId, Vec<u8>>::new();
            for chunk in &package.chunks {
                let bytes = fs::read(package_root.join(DELTA_CHUNK_DIR).join(&chunk.file_name))
                    .map_err(|err| {
                        format!("read delta package chunk {}: {err}", chunk.file_name)
                    })?;
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != chunk.size_bytes {
                    return Err(format!(
                        "delta package chunk {} size mismatch",
                        chunk.file_name
                    ));
                }
                let content_id = ContentId::from_bytes(&bytes);
                if content_id.to_hex() != chunk.content_id_hex {
                    return Err(format!(
                        "delta package chunk {} hash mismatch",
                        chunk.file_name
                    ));
                }
                decoded.insert(content_id, bytes);
            }

            let rebuilt =
                rebuild_delta_files(&target_manifest, &prior_store, &decoded, &package.entries)?;
            for (entry, bytes) in package.entries.iter().zip(rebuilt) {
                let out_path = if package.target_is_directory {
                    target_root.join(&entry.rel_path)
                } else {
                    target_root.clone()
                };
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent).map_err(|err| {
                        format!("create delta output {}: {err}", parent.display())
                    })?;
                }
                fs::write(&out_path, bytes)
                    .map_err(|err| format!("write delta output {}: {err}", out_path.display()))?;
            }

            write_delta_state(
                dest,
                &DeltaMaterial {
                    root_name: package.target_root_name,
                    is_directory: package.target_is_directory,
                    entries: package.entries,
                    manifest: target_manifest,
                    store: prior_store,
                },
            )
        }

        fn rebuild_delta_files(
            manifest: &PersistentChunkManifest,
            receiver_store: &DeltaChunkStore,
            decoded: &BTreeMap<ContentId, Vec<u8>>,
            entries: &[DeltaPackageEntry],
        ) -> Result<Vec<Vec<u8>>, String> {
            let mut files = Vec::with_capacity(entries.len());
            let mut chunk_index = 0usize;
            let mut chunk_offset = 0usize;
            for entry in entries {
                let mut remaining = entry.size_bytes;
                let mut out = Vec::with_capacity(usize::try_from(entry.size_bytes).unwrap_or(0));
                while remaining > 0 {
                    let chunk = manifest
                        .chunks
                        .get(chunk_index)
                        .ok_or_else(|| "delta package manifest ended before entries".to_string())?;
                    let bytes = receiver_store
                        .get(&chunk.content_id)
                        .or_else(|| decoded.get(&chunk.content_id).map(Vec::as_slice))
                        .ok_or_else(|| {
                            format!("delta package missing chunk {}", chunk.content_id)
                        })?;
                    let available = bytes.len().saturating_sub(chunk_offset);
                    let take = available.min(usize::try_from(remaining).unwrap_or(usize::MAX));
                    if take == 0 {
                        return Err("delta package encountered empty chunk slice".to_string());
                    }
                    out.extend_from_slice(&bytes[chunk_offset..chunk_offset + take]);
                    remaining -= u64::try_from(take).unwrap_or(remaining);
                    chunk_offset += take;
                    if chunk_offset == bytes.len() {
                        chunk_index += 1;
                        chunk_offset = 0;
                    }
                }
                files.push(out);
            }
            Ok(files)
        }

        fn refresh_delta_state_from_report(
            dest: &Path,
            report: &ReceiveReport,
        ) -> Result<(), String> {
            let mut roots = BTreeMap::<String, usize>::new();
            for path in &report.committed_paths {
                let Ok(rel) = path.strip_prefix(dest) else {
                    continue;
                };
                if let Some(first) = rel.components().next() {
                    let root = first.as_os_str().to_string_lossy().into_owned();
                    *roots.entry(root).or_insert(0) += 1;
                }
            }
            let Some((root_name, _)) = roots.into_iter().next() else {
                return Ok(());
            };
            let root_path = dest.join(root_name);
            if !root_path.exists() {
                return Ok(());
            }
            let material = build_delta_material_from_path(&root_path)?;
            write_delta_state(dest, &material)
        }

        fn write_delta_state(dest: &Path, material: &DeltaMaterial) -> Result<(), String> {
            let state_dir = dest.join(DELTA_STATE_DIR);
            fs::create_dir_all(&state_dir)
                .map_err(|err| format!("create delta state dir {}: {err}", state_dir.display()))?;
            let state = DeltaState {
                schema: DELTA_STATE_SCHEMA.to_string(),
                root_name: material.root_name.clone(),
                is_directory: material.is_directory,
                manifest_hex: hex::encode(material.manifest.to_canonical_bytes()),
                updated_unix_secs: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|err| format!("system clock before unix epoch: {err}"))?
                    .as_secs(),
            };
            let bytes = serde_json::to_vec_pretty(&state)
                .map_err(|err| format!("encode delta state: {err}"))?;
            fs::write(state_dir.join(DELTA_STATE_FILE), bytes)
                .map_err(|err| format!("write delta state: {err}"))
        }

        fn delta_chunk_file_name(content_id: &ContentId, size_bytes: u64) -> String {
            format!("{}-{size_bytes:016x}.chunk", content_id.to_hex())
        }

        fn decode_hex(raw: &str, label: &str) -> Result<Vec<u8>, String> {
            hex::decode(raw).map_err(|err| format!("decode {label} hex: {err}"))
        }
    }
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
    let delta_enabled = !args.no_delta;

    match args.transport {
        Transport::Auto => Err(
            "atp recv/serve --transport auto is sender-only; choose tcp, rq, or quic".to_string(),
        ),
        Transport::Tcp => {
            let cfg = tcp_config(args.max_bytes, !args.no_delta);
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
                    let start = Instant::now();
                    let report: ReceiveReport =
                        transport_tcp::receive_once(&cx, &listener, &dest, cfg, &peer_id)
                            .await
                            .map_err(|e| e.to_string())?;
                    let elapsed = start.elapsed();
                    handle_post_receive_delta(&dest, delta_enabled)?;
                    print_atp_metrics_line(
                        "receive",
                        Transport::Tcp,
                        report.bytes_received,
                        None,
                        Some(report.symbols_accepted),
                        report.feedback_rounds,
                        Some(report.decode_micros),
                        1,
                        Some(elapsed),
                    );
                    print_json(&tcp_recv_json(&report, Some(elapsed)));
                    Ok::<(), String>(())
                } else {
                    let delta_dest = dest.clone();
                    transport_tcp::serve(&cx, listener, dest.clone(), cfg, peer_id.clone(), |o| {
                        match o {
                            Ok(r) => {
                                if let Err(err) =
                                    handle_post_receive_delta(&delta_dest, delta_enabled)
                                {
                                    eprintln!("atp: delta receiver failed: {err}");
                                }
                                print_atp_metrics_line(
                                    "receive",
                                    Transport::Tcp,
                                    r.bytes_received,
                                    None,
                                    Some(r.symbols_accepted),
                                    r.feedback_rounds,
                                    Some(r.decode_micros),
                                    1,
                                    None,
                                );
                                print_json(&tcp_recv_json(&r, None));
                            }
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
                args.max_block_size.effective(args.symbol_size)?,
                args.repair_overhead,
                args.rq_round0_loss_pct,
                args.rq_tail_drain_ms,
                args.rq_auth_key_hex.as_deref(),
                args.rq_allow_unauthenticated_lab,
            )?;
            let chosen_fanout = cfg.udp_fanout.max(1);
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("receiver cx");
                asupersync::fs::create_dir_all(&dest)
                    .await
                    .map_err(|e| format!("create dest {}: {e}", dest.display()))?;
                let listener = TcpListener::bind(listen)
                    .await
                    .map_err(|e| format!("bind {listen}: {e}"))?;
                let bound = listener.local_addr().map_err(|e| e.to_string())?;
                let _delta_state_server =
                    spawn_delta_state_server(dest.clone(), bound, delta_enabled);
                eprintln!(
                    "atp: rq control listening on {bound} (udp on {udp_bind_ip}), dest {}",
                    dest.display()
                );
                if one_shot {
                    let start = Instant::now();
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
                    let elapsed = start.elapsed();
                    handle_post_receive_delta(&dest, delta_enabled)?;
                    print_atp_metrics_line(
                        "receive",
                        Transport::Rq,
                        report.bytes_received,
                        None,
                        Some(report.symbols_accepted),
                        report.feedback_rounds,
                        None,
                        chosen_fanout,
                        Some(elapsed),
                    );
                    print_json(&rq_recv_json(&report, chosen_fanout, Some(elapsed)));
                    Ok::<(), String>(())
                } else {
                    let delta_dest = dest.clone();
                    transport_rq::serve(
                        &cx,
                        listener,
                        udp_bind_ip.clone(),
                        dest.clone(),
                        cfg,
                        peer_id.clone(),
                        |o| match o {
                            Ok(r) => {
                                if let Err(err) =
                                    handle_post_receive_delta(&delta_dest, delta_enabled)
                                {
                                    eprintln!("atp: delta receiver failed: {err}");
                                }
                                print_atp_metrics_line(
                                    "receive",
                                    Transport::Rq,
                                    r.bytes_received,
                                    None,
                                    Some(r.symbols_accepted),
                                    r.feedback_rounds,
                                    None,
                                    chosen_fanout,
                                    None,
                                );
                                print_json(&rq_recv_json(&r, chosen_fanout, None));
                            }
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
                let chosen_fanout = cfg.datagram_fanout.max(1);
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
                        let _delta_state_server = spawn_delta_state_server(
                            dest.clone(),
                            endpoint.local_addr(),
                            delta_enabled,
                        );
                        eprintln!(
                            "atp: quic listening on {}, dest {}",
                            endpoint.local_addr(),
                            dest.display()
                        );
                        let start = Instant::now();
                        let report = receive_on_endpoint(&cx, endpoint, &dest, &cfg, &peer_id)
                            .await
                            .map_err(|e| e.to_string())?;
                        let elapsed = start.elapsed();
                        handle_post_receive_delta(&dest, delta_enabled)?;
                        print_atp_metrics_line(
                            "receive",
                            Transport::Quic,
                            report.bytes_received,
                            None,
                            Some(report.symbols_accepted),
                            report.feedback_rounds,
                            Some(report.decode_micros),
                            chosen_fanout,
                            Some(elapsed),
                        );
                        print_json(&quic_recv_json(&report, chosen_fanout, Some(elapsed)));
                        Ok::<(), String>(())
                    } else {
                        eprintln!("atp: quic listening on {listen}, dest {}", dest.display());
                        let _delta_state_server =
                            spawn_delta_state_server(dest.clone(), listen, delta_enabled);
                        // Each accepted transfer consumes the endpoint; rebind the
                        // same address for the next one. `--listen` must use a fixed
                        // port for persistent serving (port 0 would drift).
                        loop {
                            let endpoint = bind_server_endpoint(&cx, listen)
                                .await
                                .map_err(|e| e.to_string())?;
                            match receive_on_endpoint(&cx, endpoint, &dest, &cfg, &peer_id).await {
                                Ok(r) => {
                                    if let Err(err) =
                                        handle_post_receive_delta(&dest, delta_enabled)
                                    {
                                        eprintln!("atp: delta receiver failed: {err}");
                                    }
                                    print_atp_metrics_line(
                                        "receive",
                                        Transport::Quic,
                                        r.bytes_received,
                                        None,
                                        Some(r.symbols_accepted),
                                        r.feedback_rounds,
                                        Some(r.decode_micros),
                                        chosen_fanout,
                                        None,
                                    );
                                    print_json(&quic_recv_json(&r, chosen_fanout, None));
                                }
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

fn tcp_recv_json(report: &ReceiveReport, elapsed: Option<Duration>) -> serde_json::Value {
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
        "metrics": atp_metrics_json(
            report.bytes_received,
            None,
            Some(report.symbols_accepted),
            report.feedback_rounds,
            Some(report.decode_count),
            Some(report.decode_micros),
            1,
            elapsed,
        ),
        "committed_paths": report.committed_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "peer": report.peer.to_string(),
    })
}

fn tcp_send_json(report: &SendReport, elapsed: Option<Duration>) -> serde_json::Value {
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
        "metrics": atp_metrics_json(
            report.bytes_sent,
            Some(report.symbols_sent),
            Some(report.receipt.symbols_accepted),
            report.feedback_rounds,
            Some(report.receipt.decode_count),
            Some(report.receipt.decode_micros),
            1,
            elapsed,
        ),
        "peer": report.peer.to_string(),
    })
}

fn rq_recv_json(
    report: &transport_rq::ReceiveReport,
    chosen_fanout: usize,
    elapsed: Option<Duration>,
) -> serde_json::Value {
    serde_json::json!({
        "event": "atp_receive", "transport": "rq",
        "transfer_id": report.transfer_id,
        "committed": report.committed,
        "bytes_received": report.bytes_received,
        "files": report.files,
        "symbols_accepted": report.symbols_accepted,
        "feedback_rounds": report.feedback_rounds,
        "metrics": atp_metrics_json(
            report.bytes_received,
            None,
            Some(report.symbols_accepted),
            report.feedback_rounds,
            None,
            None,
            chosen_fanout,
            elapsed,
        ),
        "committed_paths": report.committed_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "peer": report.peer.to_string(),
    })
}

fn rq_send_json(
    report: &transport_rq::SendReport,
    chosen_fanout: usize,
    elapsed: Option<Duration>,
) -> serde_json::Value {
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
        "metrics": atp_metrics_json(
            report.bytes_sent,
            Some(report.symbols_sent),
            Some(report.receipt.symbols_accepted),
            report.feedback_rounds,
            None,
            None,
            chosen_fanout,
            elapsed,
        ),
        "peer": report.peer.to_string(),
    })
}

#[cfg(feature = "tls")]
fn quic_recv_json(
    report: &asupersync::net::atp::transport_quic::ReceiveReport,
    chosen_fanout: usize,
    elapsed: Option<Duration>,
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
        "metrics": atp_metrics_json(
            report.bytes_received,
            None,
            Some(report.symbols_accepted),
            report.feedback_rounds,
            Some(report.decode_count),
            Some(report.decode_micros),
            chosen_fanout,
            elapsed,
        ),
        "committed_paths": report.committed_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "peer": report.peer.to_string(),
    })
}

#[cfg(feature = "tls")]
fn quic_send_json(
    report: &asupersync::net::atp::transport_quic::SendReport,
    chosen_fanout: usize,
    elapsed: Option<Duration>,
) -> serde_json::Value {
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
        "metrics": atp_metrics_json(
            report.bytes_sent,
            Some(report.symbols_sent),
            Some(report.receipt.symbols_accepted),
            report.feedback_rounds,
            Some(report.receipt.decode_count),
            Some(report.receipt.decode_micros),
            chosen_fanout,
            elapsed,
        ),
        "peer": report.peer.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    #[cfg(feature = "tls")]
    const QUIC_PINNED_LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBwTCCAWigAwIBAgIUTQyiZ96ufyKHVqRYRZBXpRQABGMwCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMYXRwcS10ZXN0LWNhMCAXDTI2MDYxNjA1MTYyM1oYDzIxMjYw\n\
NTIzMDUxNjIzWjAUMRIwEAYDVQQDDAlhdHBxLXRlc3QwWTATBgcqhkjOPQIBBggq\n\
hkjOPQMBBwNCAASqge/wCghqQ7mK2i0YFNQQqYuxtyBbxlDvlrJDWhuXLXcrwcK4\n\
eQkpN3QBVt6JLUpAuYpUrQYUSL28G0cYl4hdo4GSMIGPMBoGA1UdEQQTMBGCCWxv\n\
Y2FsaG9zdIcEfwAAATATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA\n\
MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUTWWIxYJyvXlJNVcDd8An36rhuMQw\n\
HwYDVR0jBBgwFoAUG872eUJJNl9C6SZHmR9sCRNzvtYwCgYIKoZIzj0EAwIDRwAw\n\
RAIgOkNWPyvljX7zxCWN9sJ/rpX7XV5ubXvNrPdV70sF8oECIGtMuJr6XEmcump1\n\
YuX2YYZ2gAU6aNU/up/PediXcN5u\n\
-----END CERTIFICATE-----\n";

    #[cfg(feature = "tls")]
    fn parse_quic_pinned_leaf_cert() -> rustls::pki_types::CertificateDer<'static> {
        let mut reader = std::io::BufReader::new(QUIC_PINNED_LEAF_CERT_PEM.as_bytes());
        rustls_pemfile::certs(&mut reader)
            .next()
            .expect("one cert")
            .expect("valid cert pem")
    }

    #[cfg(feature = "tls")]
    fn quic_fixture_valid_time() -> rustls::pki_types::UnixTime {
        rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000))
    }

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
        let missing = match rq_config(1024, 1024, 1, 512 * 1024, 1.0, 0.0, 2, None, false) {
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
                0.0,
                2,
                Some(VALID_KEY_HEX),
                false
            )
            .is_ok()
        );
        assert!(rq_config(1024, 1024, 1, 512 * 1024, 1.0, 0.0, 2, None, true).is_ok());
    }

    #[test]
    fn rq_config_applies_max_block_size_for_e4_sweeps() {
        let config = rq_config(
            10 * 1024 * 1024,
            1024,
            4,
            512 * 1024,
            1.0,
            2.0,
            2,
            Some(VALID_KEY_HEX),
            false,
        )
        .expect("authenticated rq config should build");

        assert_eq!(config.max_block_size, 512 * 1024);
        assert_eq!(config.max_block_size / usize::from(config.symbol_size), 512);
        assert_eq!(config.round0_loss_target, 0.02);
    }

    #[test]
    fn max_block_size_arg_accepts_auto_and_numeric_overrides() {
        assert_eq!("auto".parse::<MaxBlockSizeArg>(), Ok(MaxBlockSizeArg::Auto));
        assert_eq!("AUTO".parse::<MaxBlockSizeArg>(), Ok(MaxBlockSizeArg::Auto));
        assert_eq!(
            (512 * 1024).to_string().parse::<MaxBlockSizeArg>(),
            Ok(MaxBlockSizeArg::Bytes(512 * 1024))
        );
        assert_eq!(
            "512KiB".parse::<MaxBlockSizeArg>(),
            Ok(MaxBlockSizeArg::Bytes(512 * 1024))
        );
        assert_eq!(
            "8M".parse::<MaxBlockSizeArg>(),
            Ok(MaxBlockSizeArg::Bytes(8 * 1024 * 1024))
        );
        assert_eq!("0".parse::<MaxBlockSizeArg>(), Ok(MaxBlockSizeArg::Auto));
        assert_eq!("0b".parse::<MaxBlockSizeArg>(), Ok(MaxBlockSizeArg::Auto));
        assert_eq!(
            "not-bytes".parse::<MaxBlockSizeArg>(),
            Err(
                "invalid --max-block-size \"not-bytes\": expected positive bytes, auto, 0, or K/M/G suffix"
                    .to_string()
            )
        );
    }

    #[test]
    fn max_block_size_clap_parser_accepts_auto_and_zero() {
        let send_auto = SendArgs::try_parse_from([
            "send",
            "/tmp/source",
            "127.0.0.1:8472",
            "--max-block-size",
            "auto",
        ])
        .expect("send parser should accept auto max-block-size");
        assert_eq!(send_auto.max_block_size, MaxBlockSizeArg::Auto);

        let send_zero = SendArgs::try_parse_from([
            "send",
            "/tmp/source",
            "127.0.0.1:8472",
            "--max-block-size",
            "0",
        ])
        .expect("send parser should accept zero max-block-size sentinel");
        assert_eq!(send_zero.max_block_size, MaxBlockSizeArg::Auto);

        let recv_zero = RecvArgs::try_parse_from(["recv", "/tmp/dest", "--max-block-size", "0"])
            .expect("recv parser should accept zero max-block-size sentinel");
        assert_eq!(recv_zero.max_block_size, MaxBlockSizeArg::Auto);
    }

    #[test]
    fn max_block_size_arg_auto_uses_bounded_decode_ceiling() {
        assert_eq!(
            MaxBlockSizeArg::Auto.effective(1024),
            Ok(AUTO_MAX_BLOCK_SIZE)
        );
        assert!(AUTO_MAX_BLOCK_SIZE < asupersync::net::atp::transport_rq::DEFAULT_MAX_BLOCK_SIZE);
        assert_eq!(MaxBlockSizeArg::Bytes(512).effective(1024), Ok(1024));
        assert_eq!(
            MaxBlockSizeArg::Bytes(512 * 1024).effective(1024),
            Ok(512 * 1024)
        );
        assert_eq!(MaxBlockSizeArg::Auto.remote_arg(), "auto");
        assert_eq!(MaxBlockSizeArg::Bytes(512 * 1024).remote_arg(), "524288");
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
    fn rq_round0_loss_pct_normalizes_fraction_and_rejects_invalid_values() {
        assert_eq!(normalize_loss_pct(0.0, "--rq-round0-loss-pct"), Ok(0.0));
        assert_eq!(normalize_loss_pct(0.1, "--rq-round0-loss-pct"), Ok(0.001));
        assert_eq!(normalize_loss_pct(2.0, "--rq-round0-loss-pct"), Ok(0.02));
        assert!(normalize_loss_pct(-0.1, "--rq-round0-loss-pct").is_err());
        assert!(normalize_loss_pct(100.0, "--rq-round0-loss-pct").is_err());
        assert!(normalize_loss_pct(f64::NAN, "--rq-round0-loss-pct").is_err());
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

    #[cfg(feature = "tls")]
    #[test]
    fn quic_pinned_leaf_accepts_exact_ip_san_and_server_auth() {
        let cert = parse_quic_pinned_leaf_cert();
        let server_name = rustls::pki_types::ServerName::from(
            "127.0.0.1"
                .parse::<std::net::IpAddr>()
                .expect("valid loopback IP"),
        );

        verify_quic_cli_pinned_leaf(&cert, &server_name, quic_fixture_valid_time())
            .expect("pinned leaf should verify for its IP SAN");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn quic_pinned_leaf_rejects_wrong_server_name() {
        let cert = parse_quic_pinned_leaf_cert();
        let server_name = rustls::pki_types::ServerName::try_from("not-localhost.example")
            .expect("valid DNS name");

        let err = verify_quic_cli_pinned_leaf(&cert, &server_name, quic_fixture_valid_time())
            .expect_err("wrong name must fail closed");
        assert!(matches!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName)
        ));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn quic_cli_client_config_builds_with_pinned_leaf_ca_pem() {
        use asupersync::net::quic_native::handshake_driver::ATP_QUIC_ALPN;

        let cert = parse_quic_pinned_leaf_cert();
        let config = quic_cli_client_config(vec![cert], vec![ATP_QUIC_ALPN.to_vec()])
            .expect("leaf PEM supplied via --ca should build pinned verifier");

        assert_eq!(config.alpn_protocols, vec![ATP_QUIC_ALPN.to_vec()]);
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
            Transport::auto_fallback_order(false),
            &[Transport::Quic, Transport::Rq, Transport::Tcp]
        );
        assert_eq!(Transport::Auto.cli_arg(), "auto");
    }

    #[test]
    fn auto_transport_order_uses_tcp_for_delta_resync() {
        assert_eq!(Transport::auto_fallback_order(true), &[Transport::Tcp]);
    }

    #[test]
    fn delta_tree_chunker_uses_smaller_content_defined_chunks() {
        let data = (0..(512 * 1024))
            .map(|idx| ((idx * 31 + idx / 7 + 13) % 251) as u8)
            .collect::<Vec<_>>();

        let chunks = split_delta_tree_object_chunks(&data).expect("delta chunks");
        let rebuilt = chunks.concat();
        let min_chunk = DELTA_TREE_OBJECT_MIN_CHUNK_BYTES;
        let max_chunk = DELTA_TREE_OBJECT_MAX_CHUNK_BYTES;

        assert_eq!(rebuilt, data);
        assert!(
            chunks.len() > 2,
            "256 KiB chunks would produce only two chunks"
        );
        assert!(
            chunks
                .iter()
                .take(chunks.len().saturating_sub(1))
                .all(|chunk| chunk.len() >= min_chunk && chunk.len() <= max_chunk)
        );
        assert!(
            chunks.iter().any(|chunk| chunk.len() < max_chunk),
            "gear hash should find content boundaries before the hard cap"
        );
    }

    #[test]
    fn delta_tree_chunker_resynchronizes_after_insert() {
        let mut original = (0..(768 * 1024))
            .map(|idx| ((idx * 17 + idx / 11 + 29) % 253) as u8)
            .collect::<Vec<_>>();
        let original_chunks = split_delta_tree_object_chunks(&original).expect("original chunks");
        original.splice(96 * 1024..96 * 1024, [0xA5; 257]);
        let shifted_chunks = split_delta_tree_object_chunks(&original).expect("shifted chunks");

        let original_hashes = original_chunks
            .iter()
            .map(|chunk| hex::encode(Sha256::digest(chunk)))
            .collect::<std::collections::BTreeSet<_>>();
        let shared = shifted_chunks
            .iter()
            .map(|chunk| hex::encode(Sha256::digest(chunk)))
            .filter(|hash| original_hashes.contains(hash))
            .count();

        assert!(
            shared * 2 >= original_chunks.len(),
            "content-defined chunks should resynchronize after a small insert"
        );
    }

    #[test]
    fn delta_tree_chunker_localizes_same_length_edit() {
        let original = (0..(2 * 1024 * 1024))
            .map(|idx| ((idx * 131 + idx / 17 + 91) % 251) as u8)
            .collect::<Vec<_>>();
        let mut edited = original.clone();
        let edit_start = 1024 * 1024;
        let edit_len = 100 * 1024;
        for (offset, byte) in edited[edit_start..edit_start + edit_len]
            .iter_mut()
            .enumerate()
        {
            *byte = ((offset * 73 + 19) % 251) as u8;
        }

        let original_chunks = split_delta_tree_object_chunks(&original).expect("original chunks");
        let edited_chunks = split_delta_tree_object_chunks(&edited).expect("edited chunks");
        let original_hashes = original_chunks
            .iter()
            .map(|chunk| (hex::encode(Sha256::digest(chunk)), chunk.len()))
            .collect::<std::collections::BTreeSet<_>>();
        let edited_missing_bytes = edited_chunks
            .iter()
            .filter(|chunk| {
                !original_hashes.contains(&(hex::encode(Sha256::digest(chunk)), chunk.len()))
            })
            .map(Vec::len)
            .sum::<usize>();

        assert!(
            edited_missing_bytes <= 192 * 1024,
            "100KiB same-length edit should not dirty {} bytes of delta chunks",
            edited_missing_bytes
        );
    }

    fn delta_tree_fixture_bytes(len: usize, seed: u32) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|idx| {
                state = state
                    .wrapping_mul(1_664_525)
                    .wrapping_add(1_013_904_223)
                    .wrapping_add(u32::try_from(idx & 0xffff).expect("masked index fits"));
                (state >> 16) as u8
            })
            .collect()
    }

    fn sort_delta_tree_files(files: &mut [DeltaTreeFile]) {
        files.sort_by(|left, right| left.rel_path.cmp(&right.rel_path));
    }

    #[test]
    fn delta_tree_object_move_keeps_payload_chunks_path_independent() {
        let payloads = (0..64)
            .map(|idx| delta_tree_fixture_bytes(24 * 1024 + (idx % 5) * 307, 97 + idx as u32))
            .collect::<Vec<_>>();

        let mut before = payloads
            .iter()
            .enumerate()
            .map(|(idx, bytes)| DeltaTreeFile {
                rel_path: format!("tree/a/file-{idx:02}.bin"),
                bytes: bytes.clone(),
            })
            .collect::<Vec<_>>();
        let mut after = payloads
            .iter()
            .enumerate()
            .map(|(idx, bytes)| DeltaTreeFile {
                rel_path: if idx == 0 {
                    "tree/z/file-00.bin".to_string()
                } else {
                    format!("tree/a/file-{idx:02}.bin")
                },
                bytes: bytes.clone(),
            })
            .collect::<Vec<_>>();
        sort_delta_tree_files(&mut before);
        sort_delta_tree_files(&mut after);

        let encoded = encode_delta_tree_object(&after).expect("encode moved tree object");
        let decoded = decode_delta_tree_object(&encoded).expect("decode moved tree object");
        assert_eq!(decoded.len(), after.len());
        for (observed, expected) in decoded.iter().zip(&after) {
            assert_eq!(observed.rel_path, expected.rel_path);
            assert_eq!(observed.bytes, expected.bytes);
        }

        let receiver = build_delta_snapshot_from_files(before).expect("receiver snapshot");
        let sender = build_delta_snapshot_from_files(after).expect("sender snapshot");
        let coverage = ReceiverCasCoverage::from_manifest(&receiver.manifest);
        let plan = plan_incremental_resync_with_receiver_coverage(
            &sender.manifest,
            Some(&receiver.manifest),
            &coverage,
        );

        assert_eq!(plan.mode, DeltaResyncMode::DeltaChunks);
        assert!(
            plan.missing_bytes < sender.manifest.total_size_bytes / 4,
            "tree move should not dirty the full payload table: missing={} total={}",
            plan.missing_bytes,
            sender.manifest.total_size_bytes
        );

        let package =
            build_delta_package(&sender, &plan, &receiver.manifest, &[]).expect("delta package");
        assert!(
            package.payload_bytes < sender.manifest.total_size_bytes / 4,
            "tree move package should stay proportional to path/index churn: payload={} total={}",
            package.payload_bytes,
            sender.manifest.total_size_bytes
        );
    }

    fn one_chunk_delta_snapshot(tree_id: &str, bytes: Vec<u8>) -> DeltaSourceSnapshot {
        let size_bytes = u64::try_from(bytes.len()).expect("test payload length");
        let chunk = CasChunkRef::from_bytes(0, 0, &bytes).expect("chunk ref");
        let manifest =
            PersistentChunkManifest::new(tree_id, vec![chunk.clone()]).expect("manifest");
        let object_sha256_hex = hex::encode(Sha256::digest(&bytes));
        let mut chunks_by_content = BTreeMap::new();
        chunks_by_content.insert(chunk.content_id.to_hex(), bytes);
        DeltaSourceSnapshot {
            manifest,
            chunks_by_content,
            object_sha256_hex,
            file_count: 1,
            logical_file_bytes: size_bytes,
        }
    }

    #[test]
    fn delta_package_target_manifest_prefers_base64_metadata_when_smaller() {
        let mut chunks = Vec::new();
        let mut byte_offset = 0u64;
        for index in 0..512u32 {
            let size = 512 + usize::try_from(index % 17).expect("small modulus fits");
            let bytes = delta_tree_fixture_bytes(size, index);
            let chunk = CasChunkRef::from_bytes(index, byte_offset, &bytes).expect("chunk ref");
            byte_offset = byte_offset
                .checked_add(chunk.size_bytes)
                .expect("test manifest size fits");
            chunks.push(chunk);
        }
        let manifest =
            PersistentChunkManifest::new("large-package-manifest", chunks).expect("large manifest");
        let manifest_bytes = manifest.to_canonical_bytes();
        let legacy_hex = hex::encode(&manifest_bytes);

        let (target_manifest_hex, target_manifest_b64) =
            encode_delta_package_target_manifest(&manifest_bytes);

        assert!(target_manifest_hex.is_none());
        let encoded = target_manifest_b64.expect("base64 manifest metadata");
        assert!(
            encoded.len() * 4 < legacy_hex.len() * 3,
            "base64 manifest metadata should cut hex bloat: base64={} legacy_hex={}",
            encoded.len(),
            legacy_hex.len()
        );

        let metadata = DeltaPackageMetadata {
            schema: DELTA_PACKAGE_SCHEMA.to_string(),
            target_manifest_hex: None,
            target_manifest_b64: Some(encoded),
            object_sha256_hex: hex::encode(Sha256::digest(&manifest_bytes)),
            missing_chunks: Vec::new(),
            subdelta_chunks: Vec::new(),
            repeated_chunks: Vec::new(),
        };
        let decoded =
            decode_delta_package_target_manifest(&metadata).expect("decode base64 manifest");
        assert_eq!(decoded, manifest);

        let legacy = DeltaPackageMetadata {
            schema: DELTA_PACKAGE_SCHEMA.to_string(),
            target_manifest_hex: Some(legacy_hex),
            target_manifest_b64: None,
            object_sha256_hex: metadata.object_sha256_hex,
            missing_chunks: Vec::new(),
            subdelta_chunks: Vec::new(),
            repeated_chunks: Vec::new(),
        };
        let decoded_legacy =
            decode_delta_package_target_manifest(&legacy).expect("decode legacy hex manifest");
        assert_eq!(decoded_legacy, manifest);
    }

    #[test]
    fn delta_state_omits_eager_subchunk_signatures() {
        let receiver = one_chunk_delta_snapshot("tree-a", vec![7; 64 * 1024]);
        let state = delta_cli_state_from_snapshot(&receiver).expect("receiver state");
        let encoded = serde_json::to_string(&state).expect("state json");

        assert!(state.chunk_signatures.is_empty());
        assert!(
            !encoded.contains("chunk_signatures"),
            "compact sidecar state must not eagerly ship per-chunk subchunk signatures: {encoded}"
        );
    }

    #[test]
    fn lazy_signature_response_returns_only_requested_chunks() {
        let receiver = one_chunk_delta_snapshot("tree-a", vec![3; 64 * 1024]);
        let temp = tempfile::tempdir().expect("tempdir");
        let dest = temp.path();
        let state_dir = dest.join(DELTA_STATE_DIR);
        let chunk_dir = state_dir.join(DELTA_CHUNK_DIR);
        fs::create_dir_all(&chunk_dir).expect("state chunk dir");

        let state = delta_cli_state_from_snapshot(&receiver).expect("receiver state");
        let state_path = state_dir.join(DELTA_STATE_FILE);
        fs::write(&state_path, serde_json::to_vec(&state).expect("state json"))
            .expect("write state");
        for (content_id_hex, payload) in &receiver.chunks_by_content {
            fs::write(chunk_dir.join(format!("{content_id_hex}.chunk")), payload)
                .expect("write chunk");
        }

        let chunk = &receiver.manifest.chunks[0];
        let response = build_delta_subchunk_signature_response(
            dest,
            DeltaSubchunkSignatureRequest {
                schema: DELTA_SUBCHUNK_SIGNATURE_REQUEST_SCHEMA.to_string(),
                chunks: vec![DeltaSubchunkSignatureRequestChunk {
                    content_id_hex: chunk.content_id.to_hex(),
                    size_bytes: chunk.size_bytes,
                }],
            },
        )
        .expect("signature response");

        assert_eq!(response.schema, DELTA_SUBCHUNK_SIGNATURE_RESPONSE_SCHEMA);
        assert_eq!(response.signatures.len(), 1);
        assert_eq!(
            response.signatures[0].content_id_hex,
            chunk.content_id.to_hex()
        );
        assert_eq!(response.signatures[0].size_bytes, chunk.size_bytes);
    }

    #[test]
    fn delta_package_build_uses_subdelta_when_whole_chunk_would_fallback() {
        let old = (0..(64 * 1024))
            .map(|idx| ((idx * 17 + idx / 5 + 41) % 251) as u8)
            .collect::<Vec<_>>();
        let mut new = old.clone();
        for byte in &mut new[24 * 1024..25 * 1024] {
            *byte ^= 0x5a;
        }

        let receiver = one_chunk_delta_snapshot("tree-a", old.clone());
        let sender = one_chunk_delta_snapshot("tree-a", new.clone());
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver.manifest);
        let plan = plan_incremental_resync_with_receiver_coverage(
            &sender.manifest,
            Some(&receiver.manifest),
            &receiver_coverage,
        );

        assert_eq!(plan.mode, DeltaResyncMode::FullObjectFallback);
        assert_eq!(plan.missing_bytes, sender.manifest.total_size_bytes);

        let receiver_signatures = vec![ReceiverSubchunkSignature {
            chunk: receiver.manifest.chunks[0].clone(),
            signature: delta_subchunk::signature(&old, delta_subchunk::DEFAULT_SUBBLOCK_BYTES),
        }];
        let package = build_delta_package(&sender, &plan, &receiver.manifest, &receiver_signatures)
            .expect("package");

        assert_eq!(package.whole_chunks.len(), 0);
        assert_eq!(package.subdelta_chunks.len(), 1);
        assert!(package.payload_bytes < sender.manifest.total_size_bytes);

        let subdelta = &package.subdelta_chunks[0];
        let ops = decode_subdelta_ops(&subdelta.encoded_ops).expect("sub-delta ops");
        let expected_sha256 =
            decode_sha256_hex(&subdelta.target_sha256_hex, "test target sha256").unwrap();
        let rebuilt = delta_subchunk::reconstruct_verified(&old, &ops, &expected_sha256)
            .expect("reconstruct target chunk");
        assert_eq!(rebuilt, new);
    }

    #[test]
    fn delta_package_build_fetches_overlapping_subdelta_base_after_cdc_drift() {
        let wrong_base = (0..(16 * 1024))
            .map(|idx| ((idx * 5 + 91) % 251) as u8)
            .collect::<Vec<_>>();
        let good_base = (0..(64 * 1024))
            .map(|idx| ((idx * 23 + idx / 7 + 11) % 253) as u8)
            .collect::<Vec<_>>();
        let mut target = good_base[..32 * 1024].to_vec();
        for byte in &mut target[12 * 1024..13 * 1024] {
            *byte ^= 0x63;
        }

        let sender = one_chunk_delta_snapshot("edited-file", target.clone());
        let wrong_chunk = CasChunkRef::from_bytes(0, 0, &wrong_base).expect("wrong chunk");
        let good_chunk = CasChunkRef::from_bytes(
            1,
            u64::try_from(wrong_base.len()).expect("wrong len"),
            &good_base,
        )
        .expect("good chunk");
        let receiver_manifest =
            PersistentChunkManifest::new("edited-file", vec![wrong_chunk, good_chunk.clone()])
                .expect("receiver manifest");
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver_manifest);
        let plan = plan_incremental_resync_with_receiver_coverage(
            &sender.manifest,
            Some(&receiver_manifest),
            &receiver_coverage,
        );
        assert_eq!(plan.mode, DeltaResyncMode::FullObjectFallback);

        let candidates =
            receiver_subchunk_signature_candidates(&plan, &receiver_manifest).expect("candidates");
        assert!(
            candidates
                .iter()
                .any(|chunk| delta_chunk_refs_match(chunk, &good_chunk)),
            "CLI sidecar must request overlapping bases, not only same-index bases"
        );

        let receiver_signatures = candidates
            .iter()
            .map(|chunk| {
                let payload = if delta_chunk_refs_match(chunk, &good_chunk) {
                    good_base.as_slice()
                } else {
                    wrong_base.as_slice()
                };
                ReceiverSubchunkSignature {
                    chunk: chunk.clone(),
                    signature: delta_subchunk::signature(
                        payload,
                        delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
                    ),
                }
            })
            .collect::<Vec<_>>();
        let package = build_delta_package(&sender, &plan, &receiver_manifest, &receiver_signatures)
            .expect("package");

        assert_eq!(package.whole_chunks.len(), 0);
        assert_eq!(package.subdelta_chunks.len(), 1);
        assert!(package.payload_bytes < sender.manifest.total_size_bytes / 4);
        assert_eq!(
            package.subdelta_chunks[0].base_chunk.content_id,
            good_chunk.content_id
        );

        let subdelta = &package.subdelta_chunks[0];
        let ops = decode_subdelta_ops(&subdelta.encoded_ops).expect("sub-delta ops");
        let expected_sha256 =
            decode_sha256_hex(&subdelta.target_sha256_hex, "test target sha256").unwrap();
        let rebuilt = delta_subchunk::reconstruct_verified(&good_base, &ops, &expected_sha256)
            .expect("reconstruct target chunk");
        assert_eq!(rebuilt, target);
    }

    #[test]
    fn delta_package_build_dedupes_repeated_missing_chunks() {
        let repeated = (0..(8 * 1024))
            .map(|idx| ((idx * 31 + idx / 7 + 43) % 251) as u8)
            .collect::<Vec<_>>();
        let unique = (0..(2 * 1024))
            .map(|idx| ((idx * 11 + idx / 3 + 97) % 253) as u8)
            .collect::<Vec<_>>();
        let object_bytes = [repeated.as_slice(), unique.as_slice(), repeated.as_slice()].concat();
        let chunk0 = CasChunkRef::from_bytes(0, 0, &repeated).expect("chunk 0");
        let chunk1 = CasChunkRef::from_bytes(
            1,
            u64::try_from(repeated.len()).expect("repeat len"),
            &unique,
        )
        .expect("chunk 1");
        let chunk2 = CasChunkRef::from_bytes(
            2,
            u64::try_from(repeated.len() + unique.len()).expect("offset"),
            &repeated,
        )
        .expect("chunk 2");
        let manifest =
            PersistentChunkManifest::new("tree-a", vec![chunk0.clone(), chunk1.clone(), chunk2])
                .expect("manifest");
        let mut chunks_by_content = BTreeMap::new();
        chunks_by_content.insert(chunk0.content_id.to_hex(), repeated.clone());
        chunks_by_content.insert(chunk1.content_id.to_hex(), unique.clone());
        let sender = DeltaSourceSnapshot {
            manifest,
            chunks_by_content,
            object_sha256_hex: hex::encode(Sha256::digest(&object_bytes)),
            file_count: 1,
            logical_file_bytes: u64::try_from(object_bytes.len()).expect("object len"),
        };
        let receiver_manifest =
            PersistentChunkManifest::new("tree-a", Vec::new()).expect("empty receiver manifest");
        let receiver_coverage = ReceiverCasCoverage::from_manifest(&receiver_manifest);
        let plan = plan_incremental_resync_with_receiver_coverage(
            &sender.manifest,
            Some(&receiver_manifest),
            &receiver_coverage,
        );

        let package =
            build_delta_package(&sender, &plan, &receiver_manifest, &[]).expect("package");

        assert_eq!(package.whole_chunks.len(), 2);
        assert_eq!(package.subdelta_chunks.len(), 0);
        assert_eq!(package.repeated_chunks.len(), 1);
        assert_eq!(
            package.payload_bytes,
            u64::try_from(repeated.len() + unique.len()).expect("payload len")
        );
        assert_eq!(
            package.repeated_chunks[0].chunk.content_id,
            package.whole_chunks[0].chunk.content_id
        );
    }

    #[test]
    fn delta_state_addr_uses_next_port_for_direct_sidecar() {
        let base: SocketAddr = "127.0.0.1:8472".parse().unwrap();
        assert_eq!(
            delta_state_addr(base).unwrap().to_string(),
            "127.0.0.1:8473"
        );

        let max: SocketAddr = "127.0.0.1:65535".parse().unwrap();
        assert!(delta_state_addr(max).is_none());
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
