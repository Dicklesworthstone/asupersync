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
//! - `--transport quic`: ATP over QUIC/TLS-1.3. Built into every atp binary —
//!   the required `atp-cli` feature bundles TLS and native roots.
//! - `--transport auto`: sender-side selection that tries authenticated,
//!   encrypted QUIC and records failed attempts in the JSON report. Unencrypted
//!   RQ/TCP join the ladder only with the explicit
//!   `--allow-plaintext-fallback` downgrade opt-in.
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

use std::collections::{BTreeMap, BTreeSet};
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
use asupersync::atp::delta_subchunk::{self, SubBlockSignature, SubDeltaOp};
use asupersync::atp::object::{ContentId, MetadataPolicy};
use asupersync::atp::safety::{
    portable_path_collision_key, validate_portable_path_set, validate_portable_relative_path,
};
use asupersync::cx::Cx;
use asupersync::net::TcpListener;
use asupersync::net::atp::bonding::BondTransferDescriptor;
#[cfg(test)]
use asupersync::net::atp::channel_bonding;
use asupersync::net::atp::transport_common::metadata::{
    path_is_link_or_reparse, path_is_link_or_reparse_sync,
};
use asupersync::net::atp::transport_common::{FilterSet, TransferProgress, plan_transfer};
use asupersync::net::atp::transport_rq::{
    self, DEFAULT_MAX_FEEDBACK_ROUNDS, DEFAULT_REPAIR_OVERHEAD, DEFAULT_ROUND_TAIL_DRAIN_MS,
    DEFAULT_SYMBOL_SIZE, DEFAULT_UDP_FANOUT, RqConfig, RqError,
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
const DELTA_TREE_OBJECT_MIN_CHUNK_BYTES: usize = 16 * 1024;
const DELTA_TREE_OBJECT_AVG_CHUNK_BYTES: usize = 32 * 1024;
const DELTA_TREE_OBJECT_MAX_CHUNK_BYTES: usize = 64 * 1024;
/// Gear boundary mask: log2(AVG) = 15 bits placed in the TOP of the hash.
/// Gear's low bits only carry the last few bytes of history (and freeze on
/// runs of equal bytes), while the high bits accumulate ~64 bytes through the
/// shift-add carries — masking the top bits finds boundaries on structured
/// data where a low-bit mask degenerates to max-cap-only chunks
/// (br-asupersync-iz269u).
const DELTA_TREE_OBJECT_BOUNDARY_MASK_BITS: u32 = 15;
const DELTA_TREE_OBJECT_BOUNDARY_MASK: u64 = ((1u64 << DELTA_TREE_OBJECT_BOUNDARY_MASK_BITS) - 1)
    << (64 - DELTA_TREE_OBJECT_BOUNDARY_MASK_BITS);
const _: () = assert!(
    DELTA_TREE_OBJECT_AVG_CHUNK_BYTES == 1 << DELTA_TREE_OBJECT_BOUNDARY_MASK_BITS,
    "boundary mask bits must track the average chunk size"
);
const AUTO_MAX_BLOCK_SIZE: usize = 512 * 1024;
const QUIC_AUTO_MAX_BLOCK_SIZE: usize = AUTO_MAX_BLOCK_SIZE;
const RQ_LOSSY_TAIL_DRAIN_ENABLE_LOSS: f64 = 0.005;
const RQ_BROKEN_TAIL_DRAIN_ENABLE_LOSS: f64 = 0.05;
const RQ_BAD_LINK_TAIL_DRAIN_MS: u64 = 40;
const RQ_BROKEN_LINK_TAIL_DRAIN_MS: u64 = 100;
const DEFAULT_RECV_ACCEPT_TIMEOUT_SECS: u64 = 60;
const DEFAULT_RECV_LISTEN_TIMEOUT_MS: u64 = 0;
const DIRECT_DELTA_SIDECAR_CONNECT_ATTEMPT_MS: u64 = 750;
const DIRECT_DELTA_SIDECAR_CONNECT_DEADLINE_MS: u64 = 5_000;
const DIRECT_DELTA_SIDECAR_CONNECT_RETRY_SLEEP_MS: u64 = 50;
const DIRECT_DELTA_SIDECAR_CONNECTION_DEADLINE_MS: u64 = 2_000;
const DIRECT_DELTA_SIDECAR_FIRST_BYTE_TIMEOUT_MS: u64 = 50;
/// Upper bound for any one JSON request or response on the unauthenticated
/// direct-delta sidecar. Large 4 GiB manifests can contain ~131k CDC chunks, so
/// keep enough room for legitimate state while bounding hostile allocations.
const DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES: usize = 64 * 1024 * 1024;
const DELTA_MAX_METADATA_BYTES: usize = DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES;
const DELTA_MAX_CHUNK_BYTES: usize = DELTA_TREE_OBJECT_MAX_CHUNK_BYTES;
const DELTA_MAX_SUBDELTA_OPS_BYTES: usize = DELTA_TREE_OBJECT_MAX_CHUNK_BYTES;
const DELTA_SUBDELTA_OPS_MAGIC: &[u8] = b"ASUP_ATP_DELTA_SUBCHUNK_OPS_V1\0";
const DELTA_MIN_SUBDELTA_OP_BYTES: usize = 1 + 8;
const DELTA_MIN_FILE_ENTRY_BYTES: usize = 4 + 1 + 8 + 32;
const DELTA_MIN_PAYLOAD_ENTRY_BYTES: usize = 32 + 8;
const DELTA_MAX_FILE_COUNT: usize = 1_000_000;
/// A 4 GiB object at the 16 KiB minimum CDC size has at most this many chunks.
const DIRECT_DELTA_SIDECAR_MAX_REQUEST_CHUNKS: usize = 4 * 1024 * 1024 * 1024 / 16_384;
/// Bound signature hashing and in-memory response construction before JSON
/// serialization. Each block covers 64 source bytes and expands substantially
/// in JSON, so this remains below the 64 MiB wire ceiling.
const DIRECT_DELTA_SIDECAR_MAX_SIGNATURE_BLOCKS: usize = 256 * 1024;
const DIRECT_DELTA_SIDECAR_RESPONSE_OVERHEAD_BYTES: usize = 1024;

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
    /// Donate this host's byte-identical copy as one donor of a bonded
    /// multi-donor transfer (RQ symbols; run one instance per donor host).
    #[command(name = "bond-donate")]
    BondDonate(BondDonateArgs),
    /// Receive one bonded multi-donor transfer: enroll N donors over the TCP
    /// control plane, ingest their RQ symbols into one decoder set, and
    /// commit fail-closed.
    #[command(name = "bond-recv")]
    BondRecv(BondRecvArgs),
    /// Orchestrate a bonded pull: run the bonded receiver locally and launch
    /// `atp bond-donate` on every donor host over SSH (next-gen BitTorrent
    /// pull from a fleet that holds byte-identical copies).
    #[command(name = "bond-pull")]
    BondPull(BondPullArgs),
    /// Derive and print the bonded transfer descriptor for a local source as
    /// JSON (used by `bond-pull` to fetch the agreed descriptor from a donor).
    #[command(name = "__bond-descriptor", hide = true)]
    BondDescriptor(BondDescriptorArgs),
    /// Generate a validator-accepted RQ symbol-auth key as lowercase hex.
    #[command(name = "rq-keygen")]
    RqKeygen,
    #[command(name = "__delta-state-export", hide = true)]
    DeltaStateExport { dest: PathBuf },
}

/// Which real transport to use.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Transport {
    /// Sender-side selection. Unencrypted RQ/TCP fallback requires opt-in.
    Auto,
    /// One reliable TCP stream.
    Tcp,
    /// RaptorQ fountain symbols over multiple UDP sockets (+ TCP control).
    Rq,
    /// RaptorQ fountain symbols over a real QUIC/TLS-1.3 connection: symbols ride
    /// QUIC DATAGRAMs and the ATP control protocol rides one bidirectional
    /// stream, all under a single authenticated, encrypted UDP flow. Built into
    /// every atp binary (the `atp-cli` feature bundles TLS and native roots).
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

    const fn auto_fallback_order(
        delta_enabled: bool,
        allow_plaintext_fallback: bool,
        rq_configured: bool,
    ) -> &'static [Self] {
        if delta_enabled {
            if allow_plaintext_fallback {
                &[Self::Tcp]
            } else {
                &[]
            }
        } else if allow_plaintext_fallback && rq_configured {
            &[Self::Quic, Self::Rq, Self::Tcp]
        } else if allow_plaintext_fallback {
            &[Self::Quic, Self::Tcp]
        } else {
            &[Self::Quic]
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

/// Remote command interpreter used by SSH bootstrap operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum RemoteShell {
    /// Probe for Windows OpenSSH and otherwise use a POSIX shell.
    Auto,
    /// Quote argv and environment assignments for a POSIX shell.
    Posix,
    /// Invoke Windows PowerShell through a UTF-16LE encoded command.
    Powershell,
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
    /// Remote command interpreter. Auto detects Windows OpenSSH.
    #[arg(long, value_enum, default_value_t = RemoteShell::Auto)]
    remote_shell: RemoteShell,
    /// Extra raw OpenSSH option; repeat for multiple argv words.
    #[arg(long = "ssh-option")]
    ssh_options: Vec<String>,
    /// Seconds to wait for the remote receiver to bind and print readiness.
    #[arg(long, default_value_t = 15)]
    ssh_ready_timeout_secs: u64,
    // ─── RaptorQ (`--transport rq`) tuning ───
    /// RaptorQ symbol size in bytes. Defaults per transport: 1400 on rq,
    /// auto-sized to fit one QUIC datagram (1144) on quic.
    #[arg(long)]
    symbol_size: Option<u16>,
    /// Number of RQ UDP sender/receiver socket pairs to spray across (rq only).
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
    /// is explicitly set. Direct QUIC/TLS transfers authenticate symbol bytes
    /// with QUIC 1-RTT AEAD and ignore this per-symbol HMAC key.
    #[arg(long, value_name = "HEX")]
    rq_auth_key_hex: Option<String>,
    /// Explicitly disable RQ symbol authentication for loopback/lab-only runs.
    /// Direct QUIC/TLS transfers are already transport-authenticated.
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
    /// Enable the legacy plaintext delta-state sidecar on direct RQ/QUIC sends.
    /// This can leak hashes and can spoof AlreadyInSync; trusted labs only.
    #[arg(long)]
    allow_unauthenticated_delta_sidecar: bool,
    /// Permit `--transport auto` to fall back from encrypted QUIC to unencrypted
    /// RQ and plaintext TCP. Without this opt-in, trust failures never downgrade.
    #[arg(long)]
    allow_plaintext_fallback: bool,
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
    /// Maximum seconds a one-shot receiver waits for the sender to connect.
    #[arg(long, default_value_t = DEFAULT_RECV_ACCEPT_TIMEOUT_SECS)]
    accept_timeout_secs: u64,
    /// Optional millisecond override for how long a one-shot receiver waits for
    /// the sender to connect. Pass 0 to use --accept-timeout-secs.
    #[arg(long, default_value_t = DEFAULT_RECV_LISTEN_TIMEOUT_MS)]
    listen_timeout_ms: u64,
    /// Worker threads for the local runtime.
    #[arg(long, default_value_t = 4)]
    workers: usize,
    /// RaptorQ symbol size in bytes (must match the sender). Defaults per
    /// transport: 1400 on rq, auto-sized to fit one QUIC datagram (1144) on
    /// quic — the sender's defaults, so set it explicitly only when the
    /// sender did.
    #[arg(long)]
    symbol_size: Option<u16>,
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
    ///
    /// Direct QUIC/TLS transfers authenticate symbol bytes with QUIC 1-RTT AEAD
    /// and ignore this per-symbol HMAC key.
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
    /// Expose the legacy plaintext delta-state sidecar on listen-port + 1.
    /// This leaks receiver hashes/signatures; trusted labs only.
    #[arg(long)]
    allow_unauthenticated_delta_sidecar: bool,
}

#[derive(Parser)]
struct BondDonateArgs {
    /// Source file or directory this donor holds. Every donor must hold a
    /// byte-identical copy: the bonded descriptor is derived from these bytes,
    /// and the donor byte proof refuses to spray on any mismatch.
    source: PathBuf,
    /// Receiver bonded CONTROL address (host:port, TCP). The donor enrolls
    /// there, receives its donor index/count and UDP symbol endpoints from the
    /// receiver, sprays its assigned fountain slice, then serves aggregated
    /// feedback until the receiver broadcasts its fail-closed commit receipt.
    #[arg(long = "to", value_name = "HOST:PORT")]
    to: String,
    /// Maximum transfer size in bytes.
    #[arg(long, default_value_t = DEFAULT_MAX_TRANSFER_BYTES)]
    max_bytes: u64,
    /// Worker threads for the local runtime.
    #[arg(long, default_value_t = 4)]
    workers: usize,
    /// RaptorQ symbol size in bytes (default 1400). Must be identical on every
    /// donor and the receiver: it is part of the agreed bonded descriptor.
    #[arg(long)]
    symbol_size: Option<u16>,
    /// Maximum RaptorQ source-block size in bytes, `auto`, or `0`. Must be
    /// identical on every donor and the receiver: it fixes per-block K in the
    /// agreed bonded descriptor.
    #[arg(
        long,
        default_value_t = MaxBlockSizeArg::Auto,
        value_parser = parse_max_block_size_arg
    )]
    max_block_size: MaxBlockSizeArg,
    /// Round-0 repair overhead factor, >= 1.0.
    #[arg(long, default_value_t = DEFAULT_REPAIR_OVERHEAD)]
    repair_overhead: f64,
    /// Hex-encoded 32-byte RQ symbol-auth key, or set ATP_RQ_AUTH_KEY_HEX.
    /// All bonded donors and the receiver must share the same key.
    #[arg(long, value_name = "HEX")]
    rq_auth_key_hex: Option<String>,
    /// Explicitly disable RQ symbol authentication for loopback/lab-only runs.
    #[arg(long)]
    rq_allow_unauthenticated_lab: bool,
}

#[derive(Parser)]
struct BondRecvArgs {
    /// Destination directory for the committed bonded transfer.
    dest: PathBuf,
    /// Local byte-identical copy of the transfer content, used to derive the
    /// agreed bonded descriptor (the exact derivation every donor runs). The
    /// landed enrollment protocol never transmits the descriptor: donors and
    /// the receiver each derive it from their own bytes and enrollment fails
    /// closed on any transfer-id / merkle-root / metadata mismatch.
    source: PathBuf,
    /// TCP control address to listen on for donor enrollment (donors dial
    /// this with `bond-donate --to`).
    #[arg(long, default_value = "0.0.0.0:8473")]
    listen: SocketAddr,
    /// Exact number of donors that must enroll before the transfer runs.
    #[arg(long = "expect-donors", value_name = "N")]
    expect_donors: u32,
    /// IP the bonded UDP symbol sockets bind on. Defaults to the --listen IP.
    #[arg(long = "udp-bind", value_name = "IP")]
    udp_bind: Option<String>,
    /// This peer's advertised identity label.
    #[arg(long, default_value = "atp-bond-receiver")]
    peer_id: String,
    /// Maximum transfer size in bytes.
    #[arg(long, default_value_t = DEFAULT_MAX_TRANSFER_BYTES)]
    max_bytes: u64,
    /// Worker threads for the local runtime.
    #[arg(long, default_value_t = 4)]
    workers: usize,
    /// Maximum seconds to wait for each donor enrollment accept and for donor
    /// symbol/control progress before failing closed.
    #[arg(long, default_value_t = DEFAULT_RECV_ACCEPT_TIMEOUT_SECS)]
    accept_timeout_secs: u64,
    /// RaptorQ symbol size in bytes (default 1400). Must match every donor.
    #[arg(long)]
    symbol_size: Option<u16>,
    /// Maximum RaptorQ source-block size in bytes, `auto`, or `0`. Must match
    /// every donor.
    #[arg(
        long,
        default_value_t = MaxBlockSizeArg::Auto,
        value_parser = parse_max_block_size_arg
    )]
    max_block_size: MaxBlockSizeArg,
    /// Round-0 repair overhead factor, >= 1.0.
    #[arg(long, default_value_t = DEFAULT_REPAIR_OVERHEAD)]
    repair_overhead: f64,
    /// Hex-encoded 32-byte RQ symbol-auth key, or set ATP_RQ_AUTH_KEY_HEX.
    /// All bonded donors and the receiver must share the same key.
    #[arg(long, value_name = "HEX")]
    rq_auth_key_hex: Option<String>,
    /// Explicitly disable RQ symbol authentication for loopback/lab-only runs.
    #[arg(long)]
    rq_allow_unauthenticated_lab: bool,
}

#[derive(Parser)]
struct BondPullArgs {
    /// Path ON EVERY DONOR HOST of the byte-identical source to pull.
    source: String,
    /// Local destination directory for the committed transfer.
    dest: PathBuf,
    /// Comma-separated donor SSH hosts (`user@host` or `host`); one
    /// `bond-donate` leg is launched on each.
    #[arg(long, value_delimiter = ',', required = true, value_name = "HOSTS")]
    donors: Vec<String>,
    /// Control address (ip:port) the donors dial back. REQUIRED unless
    /// --listen names a routable IP (then donors dial the --listen address
    /// itself). There is deliberately no inference from the SSH connection:
    /// the address this host uses to reach a donor says nothing about which
    /// address that donor can reach this host on. Keep it explicit.
    #[arg(long, value_name = "IP:PORT")]
    advertise: Option<SocketAddr>,
    /// Local TCP control address the bonded receiver listens on.
    #[arg(long, default_value = "0.0.0.0:8473")]
    listen: SocketAddr,
    /// IP the bonded UDP symbol sockets bind on. Defaults to the --listen IP.
    #[arg(long = "udp-bind", value_name = "IP")]
    udp_bind: Option<String>,
    /// Remote `atp` binary path or command name on the donor hosts.
    #[arg(long, default_value = "atp")]
    remote_atp: String,
    /// Remote donor command interpreter. Auto probes each SSH host.
    #[arg(long, value_enum, default_value_t = RemoteShell::Auto)]
    remote_shell: RemoteShell,
    /// Extra raw OpenSSH option; repeat for multiple argv words.
    #[arg(long = "ssh-option")]
    ssh_options: Vec<String>,
    /// Seconds to wait for the remote descriptor derivation (a full source
    /// hash pass on the first donor) before failing closed.
    #[arg(long, default_value_t = 300)]
    descriptor_timeout_secs: u64,
    /// This peer's advertised identity label.
    #[arg(long, default_value = "atp-bond-pull")]
    peer_id: String,
    /// Maximum transfer size in bytes.
    #[arg(long, default_value_t = DEFAULT_MAX_TRANSFER_BYTES)]
    max_bytes: u64,
    /// Worker threads for the local runtime.
    #[arg(long, default_value_t = 4)]
    workers: usize,
    /// Maximum seconds to wait for each donor enrollment accept and for donor
    /// symbol/control progress before failing closed.
    #[arg(long, default_value_t = DEFAULT_RECV_ACCEPT_TIMEOUT_SECS)]
    accept_timeout_secs: u64,
    /// RaptorQ symbol size in bytes (default 1400 on every leg).
    #[arg(long)]
    symbol_size: Option<u16>,
    /// Maximum RaptorQ source-block size in bytes, `auto`, or `0` (forwarded
    /// to every donor so all legs agree).
    #[arg(
        long,
        default_value_t = MaxBlockSizeArg::Auto,
        value_parser = parse_max_block_size_arg
    )]
    max_block_size: MaxBlockSizeArg,
    /// Round-0 repair overhead factor, >= 1.0 (forwarded to every donor).
    #[arg(long, default_value_t = DEFAULT_REPAIR_OVERHEAD)]
    repair_overhead: f64,
    /// Hex-encoded 32-byte RQ symbol-auth key, or set ATP_RQ_AUTH_KEY_HEX.
    /// Generated per-transfer when omitted and exported to the donors over
    /// SSH (mirrors the `atp send` SSH bootstrap).
    #[arg(long, value_name = "HEX")]
    rq_auth_key_hex: Option<String>,
    /// Explicitly disable RQ symbol authentication for loopback/lab-only runs.
    #[arg(long)]
    rq_allow_unauthenticated_lab: bool,
}

#[derive(Parser)]
struct BondDescriptorArgs {
    /// Source file or directory to derive the bonded descriptor from.
    source: PathBuf,
    /// Maximum transfer size in bytes.
    #[arg(long, default_value_t = DEFAULT_MAX_TRANSFER_BYTES)]
    max_bytes: u64,
    /// Worker threads for the local runtime.
    #[arg(long, default_value_t = 2)]
    workers: usize,
    /// RaptorQ symbol size in bytes (default 1400).
    #[arg(long)]
    symbol_size: Option<u16>,
    /// Maximum RaptorQ source-block size in bytes, `auto`, or `0`.
    #[arg(
        long,
        default_value_t = MaxBlockSizeArg::Auto,
        value_parser = parse_max_block_size_arg
    )]
    max_block_size: MaxBlockSizeArg,
    /// Hex-encoded 32-byte RQ symbol-auth key, or set ATP_RQ_AUTH_KEY_HEX.
    #[arg(long, value_name = "HEX")]
    rq_auth_key_hex: Option<String>,
    /// Explicitly disable RQ symbol authentication for loopback/lab-only runs.
    #[arg(long)]
    rq_allow_unauthenticated_lab: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum MaxBlockSizeArg {
    #[default]
    Auto,
    Bytes(usize),
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
        self.effective_with_auto(symbol_size, AUTO_MAX_BLOCK_SIZE)
    }

    fn effective_for_quic(self, symbol_size: u16) -> Result<usize, String> {
        self.effective_with_auto(symbol_size, QUIC_AUTO_MAX_BLOCK_SIZE)
    }

    fn effective_with_auto(
        self,
        symbol_size: u16,
        auto_max_block_size: usize,
    ) -> Result<usize, String> {
        match self {
            Self::Auto => normalize_max_block_size(symbol_size, auto_max_block_size),
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
        metadata_policy: selected_cli_metadata_policy(),
        preserve_hardlinks: true,
        ..TransferConfig::default()
    }
}

fn selected_cli_metadata_policy() -> MetadataPolicy {
    MetadataPolicy {
        preserve_timestamps: true,
        ..MetadataPolicy::default()
    }
}

fn tcp_receive_config(max_bytes: u64, enable_delta: bool, one_shot: bool) -> TransferConfig {
    let mut config = tcp_config(max_bytes, enable_delta);
    if !one_shot {
        // Delta refresh and commit mutate one destination-wide state tree.
        config.max_active_connections = 1;
    }
    config
}

fn recv_accept_timeout(seconds: u64) -> Result<Duration, String> {
    if seconds == 0 {
        return Err("--accept-timeout-secs must be greater than 0".to_string());
    }
    Ok(Duration::from_secs(seconds))
}

fn recv_listen_timeout(args: &RecvArgs) -> Result<Duration, String> {
    if args.listen_timeout_ms == 0 {
        recv_accept_timeout(args.accept_timeout_secs)
    } else {
        Ok(Duration::from_millis(args.listen_timeout_ms))
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
    let tail_drain_ms = calibrated_rq_tail_drain_ms(round0_loss_target, tail_drain_ms);
    let config = RqConfig {
        symbol_size,
        udp_fanout: streams.max(1),
        max_block_size,
        repair_overhead: repair_overhead.max(1.0),
        round0_loss_target,
        max_transfer_bytes: max_bytes,
        metadata_policy: selected_cli_metadata_policy(),
        preserve_hardlinks: true,
        max_feedback_rounds: DEFAULT_MAX_FEEDBACK_ROUNDS,
        round_tail_drain: Duration::from_millis(tail_drain_ms),
        ..RqConfig::default()
    };
    let auth = resolve_rq_auth_choice(rq_auth_key_hex, rq_allow_unauthenticated_lab, false)?;
    config_with_rq_auth(config, &auth)
}

fn rq_send_config(args: &SendArgs) -> Result<RqConfig, String> {
    let symbol_size = resolved_symbol_size(args.symbol_size, false);
    rq_config(
        args.max_bytes,
        symbol_size,
        args.streams,
        args.max_block_size.effective(symbol_size)?,
        args.repair_overhead,
        args.rq_round0_loss_pct,
        args.rq_tail_drain_ms,
        args.rq_auth_key_hex.as_deref(),
        args.rq_allow_unauthenticated_lab,
    )
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

fn calibrated_rq_tail_drain_ms(round0_loss_target: f64, requested_ms: u64) -> u64 {
    if requested_ms == 0 {
        return 0;
    }
    if round0_loss_target >= RQ_BROKEN_TAIL_DRAIN_ENABLE_LOSS {
        requested_ms.max(RQ_BROKEN_LINK_TAIL_DRAIN_MS)
    } else if round0_loss_target >= RQ_LOSSY_TAIL_DRAIN_ENABLE_LOSS {
        requested_ms.max(RQ_BAD_LINK_TAIL_DRAIN_MS)
    } else {
        requested_ms
    }
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

/// Load the platform trust store without consulting environment-selected CA
/// paths. `atp-cli` enables the loader dependency directly, so an empty result is an
/// actionable host-configuration error rather than a silent empty trust store.
#[cfg(feature = "tls")]
fn reject_environment_selected_native_roots(
    cert_file: Option<&std::ffi::OsStr>,
    cert_dir: Option<&std::ffi::OsStr>,
) -> Result<(), String> {
    if cert_file.is_some() || cert_dir.is_some() {
        return Err(
            "SSL_CERT_FILE/SSL_CERT_DIR would replace the platform trust store; \
             unset them and retry, or pass the intended certificate with --ca <PEM>"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(all(feature = "tls", feature = "atp-cli"))]
fn load_native_root_certs() -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let cert_file = env::var_os("SSL_CERT_FILE");
    let cert_dir = env::var_os("SSL_CERT_DIR");
    reject_environment_selected_native_roots(cert_file.as_deref(), cert_dir.as_deref())?;
    let result = rustls_native_certs::load_native_certs();
    if result.certs.is_empty() {
        let details = result.errors.first().map_or_else(
            || "no platform certificates found".to_string(),
            ToString::to_string,
        );
        return Err(format!(
            "load system trust roots: {details}; pass --ca <PEM> explicitly"
        ));
    }
    if !result.errors.is_empty() {
        eprintln!(
            "[atp] warning: loaded {} system trust root(s) with {} rejected certificate(s)",
            result.certs.len(),
            result.errors.len()
        );
    }
    Ok(result.certs)
}

#[cfg(all(feature = "tls", not(feature = "atp-cli")))]
fn load_native_root_certs() -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    Err("this atp build has no native trust-root support; pass --ca <PEM> explicitly".to_string())
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
    pinned_leafs: Vec<Vec<u8>>,
    alpn: Vec<Vec<u8>>,
) -> Result<Arc<rustls::ClientConfig>, asupersync::net::quic_native::tls::QuicTlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut root_store = rustls::RootCertStore::empty();
    if pinned_leafs.is_empty() {
        let (accepted, rejected) = root_store.add_parsable_certificates(roots);
        if accepted == 0 {
            return Err(
                asupersync::net::quic_native::tls::QuicTlsError::CryptoProviderFailure {
                    provider: "rustls-quic-handshake",
                    code: "client_no_valid_native_roots",
                },
            );
        }
        if rejected > 0 {
            eprintln!(
                "[atp] warning: ignored {rejected} malformed or unsupported system trust root(s)"
            );
        }
    } else {
        for cert in roots {
            root_store.add(cert).map_err(|_| {
                asupersync::net::quic_native::tls::QuicTlsError::CryptoProviderFailure {
                    provider: "rustls-quic-handshake",
                    code: "client_root_add_failed",
                }
            })?;
        }
    }
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(
            |_| asupersync::net::quic_native::tls::QuicTlsError::CryptoProviderFailure {
                provider: "rustls-quic-handshake",
                code: "client_protocol_versions",
            },
        )?;
    let mut config = if pinned_leafs.is_empty() {
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        let verifier = QuicCliServerVerifier::new(root_store, pinned_leafs, provider)?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
    };
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

/// Apply the direct QUIC/TLS authentication posture to a base QUIC config.
#[cfg(feature = "tls")]
/// Resolve the effective RaptorQ symbol size for a transport.
///
/// An explicit `--symbol-size` always wins (and still fails closed downstream
/// when it cannot fit the transport, e.g. > 1144 on QUIC). Without one, each
/// transport gets a default that just works: 1400 on rq, and the largest
/// payload that fits one QUIC DATAGRAM on quic — so users never have to size
/// symbols by hand.
fn resolved_symbol_size(explicit: Option<u16>, quic: bool) -> u16 {
    explicit.unwrap_or(if quic {
        asupersync::net::atp::transport_quic::QUIC_DEFAULT_SYMBOL_SIZE
    } else {
        DEFAULT_SYMBOL_SIZE
    })
}

fn quic_with_transport_auth(
    base: asupersync::net::atp::transport_quic::QuicConfig,
    rq_auth_key_hex: Option<&str>,
    _rq_allow_unauthenticated_lab: bool,
) -> asupersync::net::atp::transport_quic::QuicConfig {
    if rq_auth_key_hex.is_some() {
        eprintln!(
            "[atp] note: --rq-auth-key-hex is ignored on --transport quic — QUIC's TLS 1.3 AEAD \
             already authenticates every symbol datagram"
        );
    }
    base.use_transport_authenticated_symbols()
}

/// Build the sending QUIC config: client TLS trust + transport auth + tuning.
#[cfg(feature = "tls")]
fn quic_config_send(
    args: &SendArgs,
) -> Result<asupersync::net::atp::transport_quic::QuicConfig, String> {
    use asupersync::net::atp::transport_quic::{QuicConfig, native_link::QuicClientTls};
    use asupersync::net::quic_native::handshake_driver::ATP_QUIC_ALPN;

    let (roots, pinned_leafs) = match args.ca.as_deref() {
        Some(path) => {
            let roots = load_cert_chain(path)?;
            let pinned_leafs = roots.iter().map(|cert| cert.as_ref().to_vec()).collect();
            (roots, pinned_leafs)
        }
        None => (load_native_root_certs()?, Vec::new()),
    };
    let name = args
        .server_name
        .clone()
        .unwrap_or_else(|| default_server_name(&args.target));
    let server_name = quic_server_name(name)?;
    let config = quic_cli_client_config(roots, pinned_leafs, vec![ATP_QUIC_ALPN.to_vec()])
        .map_err(|e| format!("build QUIC client TLS config: {e:?}"))?;

    let symbol_size = resolved_symbol_size(args.symbol_size, true);
    let base = QuicConfig {
        symbol_size,
        max_block_size: args.max_block_size.effective_for_quic(symbol_size)?,
        repair_overhead: args.repair_overhead.max(1.0),
        round0_loss_target: normalize_loss_pct(args.rq_round0_loss_pct, "--rq-round0-loss-pct")?,
        max_transfer_bytes: args.max_bytes,
        bwlimit_bps: normalize_bwlimit_bps(args.bwlimit_bps)?,
        handshake_timeout: Duration::from_millis(args.quic_handshake_timeout_ms),
        metadata_policy: selected_cli_metadata_policy(),
        preserve_hardlinks: true,
        ..QuicConfig::default()
    };
    let mut cfg = quic_with_transport_auth(
        base,
        args.rq_auth_key_hex.as_deref(),
        args.rq_allow_unauthenticated_lab,
    );
    cfg.client_tls = Some(QuicClientTls {
        server_name,
        config,
    });
    Ok(cfg)
}

/// Build the receiving QUIC config: server cert/key + transport auth + tuning.
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

    let symbol_size = resolved_symbol_size(args.symbol_size, true);
    let base = QuicConfig {
        symbol_size,
        max_block_size: args.max_block_size.effective_for_quic(symbol_size)?,
        repair_overhead: args.repair_overhead.max(1.0),
        round0_loss_target: normalize_loss_pct(args.rq_round0_loss_pct, "--rq-round0-loss-pct")?,
        max_transfer_bytes: args.max_bytes,
        accept_timeout: recv_listen_timeout(args)?,
        handshake_timeout: Duration::from_millis(args.quic_handshake_timeout_ms),
        metadata_policy: selected_cli_metadata_policy(),
        preserve_hardlinks: true,
        ..QuicConfig::default()
    };
    let mut cfg = quic_with_transport_auth(
        base,
        args.rq_auth_key_hex.as_deref(),
        args.rq_allow_unauthenticated_lab,
    );
    cfg.server_tls = Some(QuicServerTls { config });
    Ok(cfg)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RqAuthChoice {
    KeyHex(String),
    UnauthenticatedLab,
}

fn configured_rq_auth_key(explicit_key_hex: Option<&str>) -> Option<String> {
    explicit_key_hex
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            env::var(RQ_AUTH_ENV)
                .ok()
                .map(|key| key.trim().to_string())
                .filter(|key| !key.is_empty())
        })
}

fn resolve_rq_auth_choice(
    explicit_key_hex: Option<&str>,
    allow_unauthenticated_lab: bool,
    generate_if_missing: bool,
) -> Result<RqAuthChoice, String> {
    let configured_key = configured_rq_auth_key(explicit_key_hex);

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
        "elapsed_micros": elapsed.map(|duration| {
            let micros = duration.as_micros();
            micros.min(u128::from(u64::MAX)) as u64
        }),
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

fn print_rq_udp_send_acceleration_line(report: &transport_rq::UdpSendAccelerationReport) {
    eprintln!(
        "[atp] progress rq_udp_send_acceleration flushes={} datagrams={} \
         payload_bytes={} native_batch_flushes={} native_batch_datagrams={} \
         gso_flushes={} gso_datagrams={} fallback_flushes={} fallback_datagrams={} \
         partial_flushes={} error_flushes={}",
        report.flushes,
        report.datagrams,
        report.payload_bytes,
        report.native_batch_flushes,
        report.native_batch_datagrams,
        report.gso_flushes,
        report.gso_datagrams,
        report.fallback_flushes,
        report.fallback_datagrams,
        report.partial_flushes,
        report.error_flushes,
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
    validate_user_transfer_namespace(&args.source)?;
    // `--dry-run` computes the transfer plan from the source and prints it
    // without resolving the target or opening any socket (rsync `--dry-run`).
    if args.dry_run {
        return run_send_dry_run(&args);
    }
    validate_auto_security_policy(&args)?;
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

fn validate_auto_security_policy(args: &SendArgs) -> Result<(), String> {
    if args.allow_plaintext_fallback && args.transport != Transport::Auto {
        return Err("--allow-plaintext-fallback is valid only with --transport auto".to_string());
    }
    if args.transport == Transport::Auto
        && cli_content_delta_enabled(args.no_delta)
        && !args.allow_plaintext_fallback
    {
        return Err(
            "--transport auto with delta planning would select plaintext TCP; choose an explicit \
             transport, pass --no-delta for QUIC-only fail-closed selection, or explicitly \
             allow downgrade with --allow-plaintext-fallback"
                .to_string(),
        );
    }
    Ok(())
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
    let rq_cfg = (args.transport == Transport::Rq)
        .then(|| rq_send_config(args))
        .transpose()?;
    let plan_metadata_policy = rq_cfg.as_ref().map_or_else(
        || cfg.metadata_policy.clone(),
        |rq| rq.metadata_policy.clone(),
    );
    let plan_preserve_hardlinks = rq_cfg
        .as_ref()
        .map_or(cfg.preserve_hardlinks, |rq| rq.preserve_hardlinks);
    let plan = runtime
        .block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("dry-run cx");
            if let Some(rq_cfg) = rq_cfg.as_ref() {
                transport_rq::validate_source_compatibility_with_config(&source, rq_cfg)
                    .await
                    .map_err(|error| error.to_string())?;
            }
            plan_transfer(
                &cx,
                &source,
                cfg.chunk_size,
                &plan_metadata_policy,
                plan_preserve_hardlinks,
            )
            .await
            .map_err(|error| error.to_string())
        }))
        .map_err(|e| e.to_string())?;
    enforce_transfer_size("send source", plan.total_bytes, args.max_bytes)?;
    print_json(&plan);
    Ok(())
}

fn enforce_transfer_size(label: &str, total_bytes: u64, max_bytes: u64) -> Result<(), String> {
    if total_bytes > max_bytes {
        return Err(format!(
            "{label} is {total_bytes} bytes which exceeds --max-bytes {max_bytes}"
        ));
    }
    Ok(())
}

// ─── Channel bonding: `atp bond-donate` / `bond-recv` / `bond-pull` ─────────

/// Run one donor leg of a bonded multi-donor transfer (z01bbr Phase F, donor
/// side): derive the shared descriptor from the LOCAL source bytes, then run
/// the full [`transport_rq::donate_bonded`] control loop — enroll on the
/// receiver's TCP control plane (which assigns this donor's index/count and
/// UDP endpoints), spray the assigned fountain slice, and serve aggregated
/// NeedMore feedback until the receiver broadcasts its commit receipt.
///
/// The donor byte proof inside the donate path re-hashes this host's bytes
/// against the descriptor (per-entry SHA-256 + merkle root) before any symbol
/// is sent, so a donor whose copy has drifted refuses instead of poisoning
/// the bonded fountain.
fn run_bond_donate(args: BondDonateArgs) -> Result<(), String> {
    let control_addr = resolve(&args.to)?;
    let symbol_size = resolved_symbol_size(args.symbol_size, false);
    let config = rq_config(
        args.max_bytes,
        symbol_size,
        DEFAULT_UDP_FANOUT,
        args.max_block_size.effective(symbol_size)?,
        args.repair_overhead,
        0.0,
        DEFAULT_ROUND_TAIL_DRAIN_MS,
        args.rq_auth_key_hex.as_deref(),
        args.rq_allow_unauthenticated_lab,
    )?;
    let auth_key_id = bond_auth_key_id(
        args.rq_auth_key_hex.as_deref(),
        args.rq_allow_unauthenticated_lab,
    )?;
    let runtime = build_runtime(args.workers)?;
    let source = args.source.clone();
    let max_bytes = args.max_bytes;
    let start = Instant::now();
    let report = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("bond donor cx");
        bond_donate_transfer(&cx, &source, control_addr, config, max_bytes, auth_key_id).await
    }))?;
    let elapsed = start.elapsed();
    print_atp_metrics_line(
        "bond-donate",
        Transport::Rq,
        report.spray.udp_send_acceleration.payload_bytes,
        Some(report.symbols_sent),
        Some(report.receipt.symbols_accepted),
        report.feedback_rounds,
        None,
        report.spray.receiver_endpoints.len(),
        Some(elapsed),
    );
    print_rq_udp_send_acceleration_line(&report.spray.udp_send_acceleration);
    print_json(&bond_donate_json(&report, Some(elapsed)));
    if report.receipt.committed {
        Ok(())
    } else {
        Err(format!(
            "bonded receiver did not commit: {}",
            report
                .receipt
                .reason
                .as_deref()
                .unwrap_or("verification failed")
        ))
    }
}

/// The donor-leg body `atp bond-donate` runs (and the in-process donor leg the
/// bonded e2e drives): derive the agreed descriptor from local bytes, then run
/// the full enrollment + spray + feedback loop against the receiver's control
/// address.
async fn bond_donate_transfer(
    cx: &Cx,
    source: &Path,
    control_addr: SocketAddr,
    config: RqConfig,
    max_bytes: u64,
    auth_key_id: Option<String>,
) -> Result<transport_rq::BondedDonateReport, String> {
    let descriptor =
        derive_bond_transfer_descriptor(cx, source, &config, max_bytes, auth_key_id).await?;
    let source_root = bond_source_root(source)?;
    transport_rq::donate_bonded(cx, &descriptor, control_addr, &source_root, config)
        .await
        .map_err(|error| error.to_string())
}

/// Run the bonded receiver leg (z01bbr Phase F, receiver side): derive the
/// agreed descriptor from a LOCAL byte-identical copy — the landed enrollment
/// protocol never transmits the descriptor, it only cross-checks agreement —
/// then enroll `--expect-donors` donors and drive [`transport_rq::receive_bonded`]
/// to a fail-closed commit.
fn run_bond_recv(args: BondRecvArgs) -> Result<(), String> {
    validate_bond_expected_donors(args.expect_donors)?;
    let symbol_size = resolved_symbol_size(args.symbol_size, false);
    let mut config = rq_config(
        args.max_bytes,
        symbol_size,
        DEFAULT_UDP_FANOUT,
        args.max_block_size.effective(symbol_size)?,
        args.repair_overhead,
        0.0,
        DEFAULT_ROUND_TAIL_DRAIN_MS,
        args.rq_auth_key_hex.as_deref(),
        args.rq_allow_unauthenticated_lab,
    )?;
    config.accept_timeout = recv_accept_timeout(args.accept_timeout_secs)?;
    let auth_key_id = bond_auth_key_id(
        args.rq_auth_key_hex.as_deref(),
        args.rq_allow_unauthenticated_lab,
    )?;
    let chosen_fanout = config.udp_fanout.max(1);
    let udp_bind_ip = args
        .udp_bind
        .clone()
        .unwrap_or_else(|| args.listen.ip().to_string());
    let runtime = build_runtime(args.workers)?;
    let source = args.source.clone();
    let dest = args.dest.clone();
    let listen = args.listen;
    let expect_donors = args.expect_donors;
    let peer_id = args.peer_id.clone();
    let max_bytes = args.max_bytes;
    let start = Instant::now();
    let report = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("bond receiver cx");
        let descriptor =
            derive_bond_transfer_descriptor(&cx, &source, &config, max_bytes, auth_key_id).await?;
        bond_recv_serve(
            &cx,
            &descriptor,
            &dest,
            listen,
            &udp_bind_ip,
            expect_donors,
            config,
            &peer_id,
            None,
        )
        .await
    }))?;
    let elapsed = start.elapsed();
    print_atp_metrics_line(
        "bond-receive",
        Transport::Rq,
        report.bytes_received,
        None,
        Some(report.symbols_accepted),
        report.feedback_rounds,
        None,
        chosen_fanout,
        Some(elapsed),
    );
    print_json(&bond_recv_json(&report, chosen_fanout, Some(elapsed)));
    Ok(())
}

/// The receiver-leg body shared by `bond-recv` and `bond-pull`: create the
/// destination, bind the TCP control listener, print the readiness line, and
/// run the landed bonded receive loop to a fail-closed commit.
///
/// `on_bound` reports the actually-bound control address (for `--listen`
/// port 0 and the in-process orchestrator, which must not launch donors
/// before the listener exists).
#[allow(clippy::too_many_arguments)]
async fn bond_recv_serve(
    cx: &Cx,
    descriptor: &BondTransferDescriptor,
    dest: &Path,
    listen: SocketAddr,
    udp_bind_ip: &str,
    expected_donors: u32,
    config: RqConfig,
    peer_id: &str,
    on_bound: Option<mpsc::Sender<SocketAddr>>,
) -> Result<transport_rq::BondedReceiveReport, String> {
    create_receive_destination(dest).await?;
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| format!("bind {listen}: {e}"))?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    eprintln!(
        "atp: bonded control listening on {bound} (udp on {udp_bind_ip}), dest {}, expecting {expected_donors} donor(s)",
        dest.display()
    );
    if let Some(ready) = on_bound {
        let _ = ready.send(bound);
    }
    transport_rq::receive_bonded(
        cx,
        descriptor,
        dest,
        &listener,
        udp_bind_ip,
        expected_donors,
        config,
        peer_id,
        None,
    )
    .await
    .map_err(|error| error.to_string())
}

/// Hidden helper backing `bond-pull`'s descriptor fetch: derive the bonded
/// descriptor from local source bytes and print it as one JSON line on stdout.
fn run_bond_descriptor(args: BondDescriptorArgs) -> Result<(), String> {
    let symbol_size = resolved_symbol_size(args.symbol_size, false);
    let config = rq_config(
        args.max_bytes,
        symbol_size,
        DEFAULT_UDP_FANOUT,
        args.max_block_size.effective(symbol_size)?,
        DEFAULT_REPAIR_OVERHEAD,
        0.0,
        DEFAULT_ROUND_TAIL_DRAIN_MS,
        args.rq_auth_key_hex.as_deref(),
        args.rq_allow_unauthenticated_lab,
    )?;
    let auth_key_id = bond_auth_key_id(
        args.rq_auth_key_hex.as_deref(),
        args.rq_allow_unauthenticated_lab,
    )?;
    let runtime = build_runtime(args.workers)?;
    let source = args.source.clone();
    let max_bytes = args.max_bytes;
    let descriptor = runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("bond descriptor cx");
        derive_bond_transfer_descriptor(&cx, &source, &config, max_bytes, auth_key_id).await
    }))?;
    print_json(&descriptor);
    Ok(())
}

/// Number of donors accepted by one bonded receive.
fn validate_bond_expected_donors(expected: u32) -> Result<(), String> {
    let max = asupersync::net::atp::bonding::MAX_BONDING_DONORS;
    if expected == 0 {
        return Err("--expect-donors must be at least 1".to_string());
    }
    if expected > max {
        return Err(format!(
            "--expect-donors {expected} exceeds the bonding ceiling of {max} donors"
        ));
    }
    Ok(())
}

/// Resolve the control address donors dial back for `bond-pull`.
///
/// Explicit `--advertise` wins (and must be a real routable ip:port). Without
/// it, the `--listen` IP is reused only when it is routable (never
/// 0.0.0.0/[::]); the port comes from the actually-bound listener so
/// `--listen` port 0 still advertises the real port. Inference from the SSH
/// connection is deliberately not offered — see the `--advertise` help.
fn bond_pull_control_advertise(
    advertise: Option<SocketAddr>,
    listen: SocketAddr,
    bound_port: u16,
) -> Result<SocketAddr, String> {
    if let Some(addr) = advertise {
        if addr.ip().is_unspecified() {
            return Err(
                "--advertise must name a routable IP donors can dial, not 0.0.0.0/[::]".to_string(),
            );
        }
        if addr.port() == 0 {
            return Err("--advertise must carry the real control port, not 0".to_string());
        }
        return Ok(addr);
    }
    if listen.ip().is_unspecified() {
        return Err(
            "bond-pull cannot know which address the donors can dial: pass --advertise <ip:port> \
             (e.g. this host's LAN/Tailscale IP + the control port), or bind --listen on a \
             routable IP"
                .to_string(),
        );
    }
    Ok(SocketAddr::new(listen.ip(), bound_port))
}

/// Remote argv for one `bond-donate` leg launched over SSH by `bond-pull`.
fn bond_pull_donor_argv(args: &BondPullArgs, control: SocketAddr) -> Vec<String> {
    let mut argv = vec![
        args.remote_atp.clone(),
        "bond-donate".to_string(),
        args.source.clone(),
        "--to".to_string(),
        control.to_string(),
        "--max-bytes".to_string(),
        args.max_bytes.to_string(),
        "--workers".to_string(),
        args.workers.max(1).to_string(),
        "--max-block-size".to_string(),
        args.max_block_size.remote_arg(),
        "--repair-overhead".to_string(),
        args.repair_overhead.to_string(),
    ];
    // Forward --symbol-size only when set explicitly: every leg resolves the
    // same rq default (1400), mirroring the `atp send` SSH bootstrap.
    if let Some(symbol_size) = args.symbol_size {
        argv.push("--symbol-size".to_string());
        argv.push(symbol_size.to_string());
    }
    if args.rq_allow_unauthenticated_lab {
        argv.push("--rq-allow-unauthenticated-lab".to_string());
    }
    argv
}

/// Remote argv for the descriptor fetch `bond-pull` runs on the first donor.
fn bond_pull_descriptor_argv(args: &BondPullArgs) -> Vec<String> {
    let mut argv = vec![
        args.remote_atp.clone(),
        "__bond-descriptor".to_string(),
        args.source.clone(),
        "--max-bytes".to_string(),
        args.max_bytes.to_string(),
        "--max-block-size".to_string(),
        args.max_block_size.remote_arg(),
    ];
    if let Some(symbol_size) = args.symbol_size {
        argv.push("--symbol-size".to_string());
        argv.push(symbol_size.to_string());
    }
    if args.rq_allow_unauthenticated_lab {
        argv.push("--rq-allow-unauthenticated-lab".to_string());
    }
    argv
}

/// A child-pipe reader whose completion is joined before its output is parsed.
struct CapturedChildPipe {
    log: Arc<Mutex<String>>,
    reader: Option<thread::JoinHandle<()>>,
}

impl CapturedChildPipe {
    fn snapshot(&self) -> String {
        locked_log_snapshot(&self.log)
    }

    fn finish(&mut self) -> String {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.snapshot()
    }
}

/// Spawn a thread that drains one child pipe into a shared log string.
fn capture_child_pipe<R: Read + Send + 'static>(pipe: R) -> CapturedChildPipe {
    let log = Arc::new(Mutex::new(String::new()));
    let log_for_thread = Arc::clone(&log);
    let reader = thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            let line = line.unwrap_or_else(|err| format!("<pipe read error: {err}>"));
            if let Ok(mut log) = log_for_thread.lock() {
                log.push_str(&line);
                log.push('\n');
            }
        }
    });
    CapturedChildPipe {
        log,
        reader: Some(reader),
    }
}

fn locked_log_snapshot(log: &Arc<Mutex<String>>) -> String {
    log.lock()
        .map(|s| s.clone())
        .unwrap_or_else(|_| "<log unavailable>".to_string())
}

/// Fetch the agreed bonded descriptor from a donor host over SSH by running
/// the hidden `__bond-descriptor` derivation there (the descriptor is a pure
/// function of the source bytes + agreed symbol params, so any donor that
/// truly holds the bytes can produce it; every other donor and the receiver
/// then fail closed on any disagreement during enrollment and commit).
fn bond_pull_fetch_descriptor(
    args: &BondPullArgs,
    host: &str,
    rq_auth: &RqAuthChoice,
    remote_shell: RemoteShell,
) -> Result<BondTransferDescriptor, String> {
    let argv = bond_pull_descriptor_argv(args);
    let env_vars = match rq_auth {
        RqAuthChoice::KeyHex(key_hex) => vec![(RQ_AUTH_ENV, key_hex.as_str())],
        RqAuthChoice::UnauthenticatedLab => Vec::new(),
    };
    let remote_command = remote_shell_command(remote_shell, &env_vars, &argv)?;
    let mut command = ssh_base_command(&args.ssh_options, host);
    command
        .arg(remote_command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|err| format!("spawn ssh descriptor fetch on {host}: {err}"))?;
    let mut stdout_log = child
        .stdout
        .take()
        .map(capture_child_pipe)
        .ok_or_else(|| "ssh stdout pipe unavailable".to_string())?;
    let mut stderr_log = child
        .stderr
        .take()
        .map(capture_child_pipe)
        .ok_or_else(|| "ssh stderr pipe unavailable".to_string())?;
    let status = wait_child_timeout(
        &mut child,
        Duration::from_secs(args.descriptor_timeout_secs.max(1)),
        &format!("descriptor derivation on {host}"),
    );
    let stdout = stdout_log.finish();
    let stderr = stderr_log.finish();
    let status = status?;
    if !status.success() {
        return Err(format!(
            "descriptor derivation on {host} failed ({status}); stderr: {}",
            last_log_lines(&stderr, 8)
        ));
    }
    let descriptor = stdout
        .lines()
        .find_map(|line| serde_json::from_str::<BondTransferDescriptor>(line.trim()).ok())
        .ok_or_else(|| {
            format!(
                "descriptor derivation on {host} printed no descriptor JSON; stdout: {}",
                last_log_lines(&stdout, 4)
            )
        })?;
    descriptor
        .validate()
        .map_err(|error| format!("descriptor from {host} is invalid: {error}"))?;
    Ok(descriptor)
}

/// One donor leg launched by `bond-pull`.
struct BondPullDonorLeg {
    host: String,
    child: Child,
    stdout: CapturedChildPipe,
    stderr: CapturedChildPipe,
}

/// Orchestrate a bonded pull (z01bbr Phase F, the headline UX): fetch the
/// agreed descriptor from the first donor, start the bonded receiver
/// IN-PROCESS, then SSH-launch one `bond-donate` leg per donor host dialing
/// the explicit control address, and wait for the fail-closed commit.
fn run_bond_pull(args: BondPullArgs) -> Result<(), String> {
    let donors: Vec<String> = args
        .donors
        .iter()
        .map(|host| host.trim().to_string())
        .filter(|host| !host.is_empty())
        .collect();
    if donors.is_empty() {
        return Err("--donors must name at least one SSH host".to_string());
    }
    let expected_donors = u32::try_from(donors.len())
        .map_err(|_| format!("--donors names too many hosts: {}", donors.len()))?;
    validate_bond_expected_donors(expected_donors)?;
    let donor_shells = donors
        .iter()
        .map(|host| resolve_remote_shell(args.remote_shell, &args.ssh_options, host))
        .collect::<Result<Vec<_>, _>>()?;
    // Fail fast on an unusable control posture before any remote work.
    bond_pull_control_advertise(args.advertise, args.listen, args.listen.port())?;

    // RQ symbol auth mirrors the `atp send` SSH bootstrap: use the configured
    // key or generate a per-transfer one, and export it to every donor leg.
    let rq_auth = resolve_rq_auth_choice(
        args.rq_auth_key_hex.as_deref(),
        args.rq_allow_unauthenticated_lab,
        true,
    )?;
    let (auth_key_hex, allow_lab) = match &rq_auth {
        RqAuthChoice::KeyHex(key_hex) => (Some(key_hex.clone()), false),
        RqAuthChoice::UnauthenticatedLab => (None, true),
    };
    let symbol_size = resolved_symbol_size(args.symbol_size, false);
    let mut config = rq_config(
        args.max_bytes,
        symbol_size,
        DEFAULT_UDP_FANOUT,
        args.max_block_size.effective(symbol_size)?,
        args.repair_overhead,
        0.0,
        DEFAULT_ROUND_TAIL_DRAIN_MS,
        auth_key_hex.as_deref(),
        allow_lab,
    )?;
    config.accept_timeout = recv_accept_timeout(args.accept_timeout_secs)?;
    let chosen_fanout = config.udp_fanout.max(1);

    eprintln!(
        "atp: bond-pull fetching descriptor from {} ({} donor(s) total)",
        donors[0],
        donors.len()
    );
    let descriptor = bond_pull_fetch_descriptor(&args, &donors[0], &rq_auth, donor_shells[0])?;
    enforce_transfer_size("bond-pull source", descriptor.total_bytes, args.max_bytes)?;

    // Start the bonded receiver in-process and wait for its bound control
    // address before any donor is launched.
    let udp_bind_ip = args
        .udp_bind
        .clone()
        .unwrap_or_else(|| args.listen.ip().to_string());
    let (ready_tx, ready_rx) = mpsc::channel::<SocketAddr>();
    let start = Instant::now();
    let receiver_thread = {
        let descriptor = descriptor.clone();
        let dest = args.dest.clone();
        let listen = args.listen;
        let udp_bind_ip = udp_bind_ip.clone();
        let config = config.clone();
        let peer_id = args.peer_id.clone();
        let workers = args.workers;
        thread::spawn(
            move || -> Result<transport_rq::BondedReceiveReport, String> {
                let runtime = build_runtime(workers)?;
                runtime.block_on(runtime.handle().spawn(async move {
                    let cx = Cx::current().expect("bond pull receiver cx");
                    bond_recv_serve(
                        &cx,
                        &descriptor,
                        &dest,
                        listen,
                        &udp_bind_ip,
                        expected_donors,
                        config,
                        &peer_id,
                        Some(ready_tx),
                    )
                    .await
                }))
            },
        )
    };
    let bound = match ready_rx.recv_timeout(Duration::from_secs(30)) {
        Ok(bound) => bound,
        Err(_) => {
            let error = match receiver_thread.join() {
                Ok(Ok(_)) => "bonded receiver exited before binding".to_string(),
                Ok(Err(error)) => error,
                Err(_) => "bonded receiver thread panicked before binding".to_string(),
            };
            return Err(format!("bond-pull receiver failed to start: {error}"));
        }
    };
    let control = bond_pull_control_advertise(args.advertise, args.listen, bound.port())?;

    // Launch one bond-donate leg per donor host, all dialing the same
    // explicit control address.
    let mut legs: Vec<BondPullDonorLeg> = Vec::with_capacity(donors.len());
    let argv_control = bond_pull_donor_argv(&args, control);
    let mut spawn_error: Option<String> = None;
    for (host, remote_shell) in donors.iter().zip(donor_shells) {
        let env_vars = match &rq_auth {
            RqAuthChoice::KeyHex(key_hex) => vec![(RQ_AUTH_ENV, key_hex.as_str())],
            RqAuthChoice::UnauthenticatedLab => Vec::new(),
        };
        let remote_command = match remote_shell_command(remote_shell, &env_vars, &argv_control) {
            Ok(command) => command,
            Err(error) => {
                spawn_error = Some(format!(
                    "construct remote donor command for {host}: {error}"
                ));
                break;
            }
        };
        let mut command = ssh_base_command(&args.ssh_options, host);
        command
            .arg(remote_command)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match command.spawn() {
            Ok(mut child) => {
                let stdout = child.stdout.take().map(capture_child_pipe);
                let stderr = child.stderr.take().map(capture_child_pipe);
                let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
                    let _ = child.kill();
                    let _ = child.wait();
                    spawn_error = Some(format!("ssh pipes unavailable for donor {host}"));
                    break;
                };
                eprintln!("atp: bond-pull launched donor {host} -> {control}");
                legs.push(BondPullDonorLeg {
                    host: host.clone(),
                    child,
                    stdout,
                    stderr,
                });
            }
            Err(err) => {
                spawn_error = Some(format!("spawn ssh donor {host}: {err}"));
                break;
            }
        }
    }
    if let Some(error) = spawn_error {
        for leg in &mut legs {
            let _ = leg.child.kill();
            let _ = leg.child.wait();
            let _ = leg.stdout.finish();
            let _ = leg.stderr.finish();
        }
        // The receiver thread fails closed on its own enrollment timeout; the
        // process exits with this error either way.
        return Err(error);
    }

    // The receiver returns exactly when the transfer commits or fails closed.
    let receive_result = receiver_thread
        .join()
        .map_err(|_| "bonded receiver thread panicked".to_string())?;
    if receive_result.is_err() {
        for leg in &mut legs {
            let _ = leg.child.kill();
        }
    }

    // Collect per-donor outcomes (donors exit right after the commit receipt).
    let mut donor_outcomes = Vec::with_capacity(legs.len());
    for leg in &mut legs {
        let status = wait_child_timeout(
            &mut leg.child,
            Duration::from_secs(60),
            &format!("bond-donate leg on {}", leg.host),
        );
        let stdout = leg.stdout.finish();
        let stderr = leg.stderr.finish();
        let report = stdout
            .lines()
            .find_map(|line| serde_json::from_str::<serde_json::Value>(line.trim()).ok());
        let (exit_ok, exit_detail) = match &status {
            Ok(status) => (status.success(), status.to_string()),
            Err(error) => (false, error.clone()),
        };
        donor_outcomes.push(serde_json::json!({
            "host": leg.host,
            "exit_ok": exit_ok,
            "exit_status": exit_detail,
            "report": report,
            "stderr_tail": last_log_lines(&stderr, 5),
        }));
    }

    let elapsed = start.elapsed();
    match receive_result {
        Ok(report) => {
            print_atp_metrics_line(
                "bond-pull",
                Transport::Rq,
                report.bytes_received,
                None,
                Some(report.symbols_accepted),
                report.feedback_rounds,
                None,
                chosen_fanout,
                Some(elapsed),
            );
            print_json(&serde_json::json!({
                "event": "atp_bond_pull", "transport": "rq",
                "control_advertise": control.to_string(),
                "donor_hosts": donors,
                "receiver": bond_recv_json(&report, chosen_fanout, Some(elapsed)),
                "donors": donor_outcomes,
            }));
            Ok(())
        }
        Err(error) => {
            print_json(&serde_json::json!({
                "event": "atp_bond_pull", "transport": "rq",
                "control_advertise": control.to_string(),
                "donor_hosts": donors,
                "error": error,
                "donors": donor_outcomes,
            }));
            Err(format!("bond-pull receive failed: {error}"))
        }
    }
}

/// Derive the shared bonded-transfer descriptor from the donor's local source
/// bytes.
///
/// The bonding invariant (z01bbr Phase A) is that every donor and the receiver
/// agree on the exact same object so a `(sbn, esi)` pair names the same bytes
/// everywhere. This derivation is a pure function of the source bytes plus the
/// agreed `(symbol_size, max_block_size)` params: [`plan_transfer`] makes the
/// same deterministic sorted walk + streaming SHA-256 pass a real send commits
/// (byte-identical trees at different absolute roots and on different operating
/// systems produce identical plans),
/// the merkle root is the flat object-graph root over those digests, and the
/// transfer id is the rq derivation ([`channel_bonding::transfer_id_hex`]).
/// E-15 small-file packing and large-object splitting are deliberately NOT
/// applied: descriptor entries are the logical files themselves — exactly what
/// `donate_path`'s donor byte proof re-hashes from disk — and how a donor
/// materialises entry bytes is a donor-local concern that must not change the
/// agreed `(sbn, esi)` → bytes map.
async fn derive_bond_transfer_descriptor(
    cx: &Cx,
    source: &Path,
    config: &RqConfig,
    max_bytes: u64,
    auth_key_id: Option<String>,
) -> Result<BondTransferDescriptor, String> {
    // Single source of truth for "local bytes -> bonded descriptor": the
    // library helper preserves the `MetadataPolicy::portable()` capture and the
    // exact plan/merkle/transfer-id derivation this CLI used to inline. The CLI
    // owns only the String error surface for its human-facing diagnostics.
    asupersync::net::atp::bonding::derive_bonded_descriptor(
        cx,
        source,
        config.symbol_size,
        config.max_block_size as u64,
        max_bytes,
        auth_key_id,
    )
    .await
    .map_err(|error| error.to_string())
}

/// Derive the non-secret shared-key identifier carried in the bonded
/// descriptor and assignment.
///
/// Every donor must derive the same id from the same key material regardless
/// of whether the key arrived via `--rq-auth-key-hex` or the environment, so
/// the id is a truncated SHA-256 fingerprint of the raw key bytes — never the
/// key itself (descriptors and assignments may be logged or serialized for
/// coordination).
fn bond_auth_key_id(
    explicit_key_hex: Option<&str>,
    allow_unauthenticated_lab: bool,
) -> Result<Option<String>, String> {
    match resolve_rq_auth_choice(explicit_key_hex, allow_unauthenticated_lab, false)? {
        RqAuthChoice::UnauthenticatedLab => Ok(None),
        RqAuthChoice::KeyHex(key_hex) => {
            let mut bytes = [0u8; AUTH_KEY_SIZE];
            hex::decode_to_slice(&key_hex, &mut bytes)
                .map_err(|err| format!("decode RQ auth key hex: {err}"))?;
            let digest: [u8; 32] = Sha256::digest(bytes).into();
            Ok(Some(format!(
                "rq-auth-sha256:{}",
                hex::encode(&digest[..8])
            )))
        }
    }
}

/// Resolve the root directory whose relative entry paths back the descriptor.
///
/// The source walk keys a single-file source by its file name, so the donor
/// byte proof must resolve entries against the file's parent directory; a
/// directory source is its own root.
fn bond_source_root(source: &Path) -> Result<PathBuf, String> {
    if source.is_dir() {
        return Ok(source.to_path_buf());
    }
    source.parent().map(Path::to_path_buf).ok_or_else(|| {
        format!(
            "bond-donate source {} has no parent directory",
            source.display()
        )
    })
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
    let order = attempts
        .iter()
        .map(|attempt| attempt.transport.cli_arg())
        .collect::<Vec<_>>()
        .join(" -> ");
    format!("atp --transport auto exhausted permitted fallback order ({order}): {details}")
}

fn run_send_to_addr(
    mut args: SendArgs,
    addr: SocketAddr,
    use_direct_delta_probe: bool,
) -> Result<(), String> {
    let mut direct_delta_plan = None;
    let mut delta_package_guard = None;
    if use_direct_delta_probe && let Some(delta) = prepare_direct_delta_send(&args, addr)? {
        match delta {
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
                delta_package_guard = Some(DeltaPackageRootGuard::new(package_root.clone())?);
                args.source = package_root;
                direct_delta_plan = Some((plan, package_payload_bytes, subdelta_chunks));
            }
        }
    }

    let runtime = build_runtime(args.workers)?;
    let mut report = if args.transport == Transport::Auto {
        run_send_auto_to_addr(&runtime, &args, addr)?
    } else {
        send_to_addr_with_transport(&runtime, &args, args.transport, addr)
            .map_err(|failure| failure.message)?
    };
    if let Some((plan, package_payload_bytes, subdelta_chunks)) = direct_delta_plan.as_ref() {
        annotate_direct_delta_package_report(
            &mut report,
            plan,
            *package_payload_bytes,
            *subdelta_chunks,
        );
    }
    if let Some(mut guard) = delta_package_guard {
        guard.cleanup()?;
    }
    print_json(&report);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SendTransportFailure {
    message: String,
    fallback_eligible: bool,
}

impl SendTransportFailure {
    fn fatal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fallback_eligible: false,
        }
    }

    fn fallback_eligible(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fallback_eligible: true,
        }
    }
}

impl From<String> for SendTransportFailure {
    fn from(message: String) -> Self {
        Self::fatal(message)
    }
}

fn classify_rq_send_failure(error: RqError) -> SendTransportFailure {
    let fallback_eligible = matches!(&error, RqError::HandshakeRejected(_));
    if fallback_eligible {
        SendTransportFailure::fallback_eligible(error.to_string())
    } else {
        SendTransportFailure::fatal(error.to_string())
    }
}

#[cfg(feature = "tls")]
fn classify_quic_send_failure(
    error: asupersync::net::atp::transport_quic::QuicTransportError,
) -> SendTransportFailure {
    use asupersync::net::atp::transport_quic::QuicTransportError;

    let fallback_eligible = matches!(
        &error,
        QuicTransportError::HandshakeRejected(_)
            | QuicTransportError::Timeout {
                operation: "quic client handshake",
                ..
            }
            | QuicTransportError::Timeout {
                operation: "receive sender handshake ack",
                ..
            }
            | QuicTransportError::NotImplemented { .. }
    ) || matches!(&error, QuicTransportError::Quic(message) if message.starts_with("quic handshake: "));
    if fallback_eligible {
        SendTransportFailure::fallback_eligible(error.to_string())
    } else {
        SendTransportFailure::fatal(error.to_string())
    }
}

fn run_send_auto_to_addr(
    runtime: &asupersync::runtime::Runtime,
    args: &SendArgs,
    addr: SocketAddr,
) -> Result<serde_json::Value, String> {
    let mut attempts = Vec::new();
    let rq_configured = args.rq_allow_unauthenticated_lab
        || configured_rq_auth_key(args.rq_auth_key_hex.as_deref()).is_some();
    for transport in Transport::auto_fallback_order(
        cli_content_delta_enabled(args.no_delta),
        args.allow_plaintext_fallback,
        rq_configured,
    )
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
            Err(SendTransportFailure {
                message,
                fallback_eligible,
            }) => {
                if !fallback_eligible {
                    return Err(format!(
                        "atp --transport auto aborted after non-fallback-safe {} failure: {message}",
                        transport.cli_arg()
                    ));
                }
                eprintln!(
                    "[atp] transport selection: {} unavailable before transfer: {message}",
                    transport.cli_arg()
                );
                attempts.push(TransportAttempt {
                    transport,
                    status: TransportAttemptStatus::Failed(message),
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
) -> Result<serde_json::Value, SendTransportFailure> {
    let bwlimit_bps = normalize_bwlimit_bps(args.bwlimit_bps)?;
    if bwlimit_bps.is_some() && transport != Transport::Quic {
        return Err(SendTransportFailure::fatal(format!(
            "--bwlimit is currently wired only for quic; {} fallback skipped \
             to avoid ignoring the cap",
            transport.cli_arg()
        )));
    }

    let source = args.source.clone();
    let peer_id = args.peer_id.clone();
    match transport {
        Transport::Auto => Err(SendTransportFailure::fatal(
            "internal error: auto is a selector, not a concrete transport",
        )),
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
                .map_err(|e: TransportError| SendTransportFailure::fatal(e.to_string()))?;
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
            let cfg = rq_send_config(args)?;
            let chosen_fanout = cfg.udp_fanout.max(1);
            let start = Instant::now();
            let report = runtime
                .block_on(runtime.handle().spawn(async move {
                    let cx = Cx::current().expect("sender cx");
                    transport_rq::send_path(&cx, addr, &source, cfg, &peer_id).await
                }))
                .map_err(classify_rq_send_failure)?;
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
            print_rq_udp_send_acceleration_line(&report.udp_send_acceleration);
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
                    .map_err(classify_quic_send_failure)?;
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
                Err(SendTransportFailure::fatal(
                    "this atp binary was built without TLS (non-standard: the required atp-cli feature always bundles it) — rebuild with --features atp-cli",
                ))
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
            || remote_path.starts_with('~')
            || looks_like_windows_shell_path(remote_path);
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

fn looks_like_windows_shell_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.contains('\\')
        || value.starts_with("//")
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

fn validate_posix_ssh_path(label: &str, path: &str) -> Result<(), String> {
    if looks_like_windows_shell_path(path) {
        return Err(format!(
            "SSH bootstrap uses POSIX shell commands and cannot use Windows-style {label} path \
             {path:?}; start `atp recv` directly on Windows and send to its listener address"
        ));
    }
    Ok(())
}

fn validate_posix_ssh_bootstrap(args: &SendArgs, remote: &RemoteTarget) -> Result<(), String> {
    validate_posix_ssh_path("remote destination", &remote.remote_path)?;
    validate_posix_ssh_path("remote atp executable", &args.remote_atp)?;
    for (label, path) in [
        ("remote server certificate", args.server_cert.as_deref()),
        ("remote server key", args.server_key.as_deref()),
    ] {
        if let Some(path) = path {
            let path = path.to_string_lossy();
            validate_posix_ssh_path(label, &path)?;
        }
    }
    Ok(())
}

fn validate_ssh_bootstrap(
    shell: RemoteShell,
    args: &SendArgs,
    remote: &RemoteTarget,
) -> Result<(), String> {
    if shell == RemoteShell::Posix {
        validate_posix_ssh_bootstrap(args, remote)?;
    }
    Ok(())
}

fn run_send_via_ssh(mut args: SendArgs, remote: &RemoteTarget) -> Result<(), String> {
    let remote_shell =
        resolve_remote_shell(args.remote_shell, &args.ssh_options, &remote.ssh_host)?;
    validate_ssh_bootstrap(remote_shell, &args, remote)?;
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

    // RQ still needs a per-symbol HMAC key. Direct QUIC/TLS authenticates the
    // same symbol bytes with QUIC 1-RTT AEAD, so SSH bootstrap does not generate
    // or export an RQ auth key for that transport.
    let rq_auth = if args.transport == Transport::Rq {
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

    let data_host = choose_data_host(&args, remote, remote_shell);
    if args.transport == Transport::Quic && args.server_name.is_none() {
        args.server_name = Some(default_quic_server_name_for_ssh(remote));
    }
    let delta_package = if !cli_content_delta_enabled(args.no_delta) {
        None
    } else {
        prepare_delta_ssh_send(&args, remote, remote_shell)?
    };
    let mut delta_package_guard = None;
    if let Some(delta) = delta_package {
        match delta {
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
                delta_package_guard = Some(DeltaPackageRootGuard::new(package_root.clone())?);
                args.source = package_root;
            }
        }
    }
    let data_target = socket_target(&data_host, args.remote_listen.port());
    let addr = resolve(&data_target)?;
    let mut child = spawn_remote_receiver(&args, remote, rq_auth.as_ref(), remote_shell)?;
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

    let status = wait_child_timeout(
        &mut child,
        Duration::from_secs(60),
        "remote atp receiver (after send completion)",
    )?;
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

    if let Some(mut guard) = delta_package_guard {
        guard.cleanup()?;
    }

    Ok(())
}

#[derive(Debug)]
enum DeltaPreparedSend {
    Package {
        package_root: PathBuf,
        plan: DeltaResyncPlan,
        package_payload_bytes: u64,
        subdelta_chunks: usize,
    },
}

#[derive(Debug)]
struct DeltaPackageRootGuard {
    root: Option<PathBuf>,
}

impl DeltaPackageRootGuard {
    fn new(root: PathBuf) -> Result<Self, String> {
        let name = root
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("delta package root has no UTF-8 name: {}", root.display()))?;
        if !name.starts_with(DELTA_PACKAGE_PREFIX) {
            return Err(format!(
                "refusing to own non-package temporary path: {}",
                root.display()
            ));
        }
        Ok(Self { root: Some(root) })
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let Some(root) = self.root.take() else {
            return Ok(());
        };
        match remove_delta_path_if_exists(&root, "remove sender delta package") {
            Ok(()) => Ok(()),
            Err(error) => {
                self.root = Some(root);
                Err(error)
            }
        }
    }
}

impl Drop for DeltaPackageRootGuard {
    fn drop(&mut self) {
        if let Some(root) = self.root.take() {
            let _ = remove_delta_path_if_exists(&root, "remove sender delta package");
        }
    }
}

#[derive(Debug)]
struct DeltaSourceSnapshot {
    manifest: PersistentChunkManifest,
    chunks_by_content: BTreeMap<String, Vec<u8>>,
    object_sha256_hex: String,
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

#[derive(Debug)]
struct DeltaSnapshotBudget {
    max_bytes: u64,
    logical_bytes: u64,
}

impl DeltaSnapshotBudget {
    fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            logical_bytes: 0,
        }
    }

    fn read_file(&mut self, path: &Path) -> Result<Vec<u8>, DeltaSnapshotFailure> {
        ensure_delta_path_chain(path, "read delta snapshot file")
            .map_err(DeltaSnapshotFailure::fatal)?;
        let remaining = self.max_bytes.saturating_sub(self.logical_bytes);
        let host_limit = usize::try_from(remaining).unwrap_or(usize::MAX.saturating_sub(1));
        let mut file = fs::File::open(path).map_err(|err| {
            DeltaSnapshotFailure::fatal(format!("open delta snapshot {}: {err}", path.display()))
        })?;
        let bytes = read_file_limited_before_deadline(
            &mut file,
            host_limit,
            None,
            &format!("read delta snapshot {}", path.display()),
        )
        .map_err(DeltaSnapshotFailure::fatal)?;
        let len = u64::try_from(bytes.len()).map_err(|_| {
            DeltaSnapshotFailure::fatal("delta snapshot file length exceeds u64::MAX")
        })?;
        self.logical_bytes = self.logical_bytes.checked_add(len).ok_or_else(|| {
            DeltaSnapshotFailure::fatal("delta snapshot logical size exceeds u64::MAX")
        })?;
        if self.logical_bytes > self.max_bytes {
            return Err(DeltaSnapshotFailure::fatal(format!(
                "delta snapshot logical size {} exceeds --max-bytes {}",
                self.logical_bytes, self.max_bytes
            )));
        }
        Ok(bytes)
    }
}

#[derive(Debug)]
enum DeltaSnapshotFailure {
    UnsupportedCapability(String),
    Fatal(String),
}

impl DeltaSnapshotFailure {
    fn unsupported(message: impl Into<String>) -> Self {
        Self::UnsupportedCapability(message.into())
    }

    fn fatal(message: impl Into<String>) -> Self {
        Self::Fatal(message.into())
    }
}

impl std::fmt::Display for DeltaSnapshotFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedCapability(message) | Self::Fatal(message) => {
                formatter.write_str(message)
            }
        }
    }
}

fn delta_link_or_reparse_prefix(path: &Path, operation: &str) -> Result<Option<PathBuf>, String> {
    let mut ancestors = path
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        match fs::symlink_metadata(ancestor) {
            Ok(_) => {
                if path_is_link_or_reparse_sync(ancestor).map_err(|err| {
                    format!(
                        "inspect path prefix {} before {operation}: {err}",
                        ancestor.display()
                    )
                })? {
                    return Ok(Some(ancestor.to_path_buf()));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "inspect path prefix {} before {operation}: {err}",
                    ancestor.display()
                ));
            }
        }
    }
    Ok(None)
}

fn ensure_delta_path_chain(path: &Path, operation: &str) -> Result<(), String> {
    if let Some(prefix) = delta_link_or_reparse_prefix(path, operation)? {
        return Err(format!(
            "refusing to {operation} through symlink or reparse-point prefix {}",
            prefix.display()
        ));
    }
    Ok(())
}

fn delta_path_metadata(path: &Path, operation: &str) -> Result<Option<fs::Metadata>, String> {
    ensure_delta_path_chain(path, operation)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "inspect delta path {} before {operation}: {err}",
            path.display()
        )),
    }
}

fn require_delta_directory(path: &Path, operation: &str) -> Result<(), String> {
    let metadata = delta_path_metadata(path, operation)?
        .ok_or_else(|| format!("delta directory does not exist: {}", path.display()))?;
    if !metadata.is_dir() {
        return Err(format!("delta path is not a directory: {}", path.display()));
    }
    Ok(())
}

fn create_delta_dir(path: &Path, operation: &str) -> Result<(), String> {
    ensure_delta_path_chain(path, operation)?;
    fs::create_dir(path).map_err(|err| format!("{operation} {}: {err}", path.display()))?;
    require_delta_directory(path, operation)
}

fn create_delta_dir_all(path: &Path, operation: &str) -> Result<(), String> {
    ensure_delta_path_chain(path, operation)?;
    fs::create_dir_all(path).map_err(|err| format!("{operation} {}: {err}", path.display()))?;
    require_delta_directory(path, operation)
}

fn create_delta_file(path: &Path, operation: &str) -> Result<fs::File, String> {
    if let Some(metadata) = delta_path_metadata(path, operation)?
        && !metadata.is_file()
    {
        return Err(format!(
            "refusing to replace non-file delta path {}",
            path.display()
        ));
    }
    fs::File::create(path).map_err(|err| format!("{operation} {}: {err}", path.display()))
}

fn write_delta_file(
    file: &mut fs::File,
    path: &Path,
    bytes: &[u8],
    operation: &str,
) -> Result<(), String> {
    ensure_delta_path_chain(path, operation)?;
    file.write_all(bytes)
        .map_err(|err| format!("{operation} {}: {err}", path.display()))
}

fn read_delta_file_bounded_before(
    path: &Path,
    max_bytes: usize,
    deadline: Option<Instant>,
    operation: &str,
) -> Result<Vec<u8>, String> {
    let metadata = delta_path_metadata(path, operation)?
        .ok_or_else(|| format!("delta file does not exist: {}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "delta path is not a regular file: {}",
            path.display()
        ));
    }
    let mut file = fs::File::open(path)
        .map_err(|err| format!("open delta file {} for {operation}: {err}", path.display()))?;
    read_file_limited_before_deadline(&mut file, max_bytes, deadline, operation)
        .map_err(|err| format!("{}: {err}", path.display()))
}

fn read_delta_file_exact_before(
    path: &Path,
    declared_bytes: u64,
    hard_cap: usize,
    deadline: Option<Instant>,
    operation: &str,
) -> Result<Vec<u8>, String> {
    let expected = usize::try_from(declared_bytes)
        .map_err(|_| format!("{operation} declared size exceeds usize::MAX"))?;
    if expected > hard_cap {
        return Err(format!(
            "{operation} declared size {expected} exceeds {hard_cap} byte limit"
        ));
    }
    let bytes = read_delta_file_bounded_before(path, expected, deadline, operation)?;
    if bytes.len() != expected {
        return Err(format!(
            "{operation} size mismatch: expected {expected}, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn rename_delta_path(from: &Path, to: &Path, operation: &str) -> Result<(), String> {
    if delta_path_metadata(from, operation)?.is_none() {
        return Err(format!(
            "delta rename source does not exist: {}",
            from.display()
        ));
    }
    if delta_path_metadata(to, operation)?.is_some() {
        return Err(format!(
            "delta rename destination already exists: {}",
            to.display()
        ));
    }
    fs::rename(from, to)
        .map_err(|err| format!("{operation} {} to {}: {err}", from.display(), to.display()))
}

fn remove_delta_path_if_exists(path: &Path, operation: &str) -> Result<(), String> {
    let Some(metadata) = delta_path_metadata(path, operation)? else {
        return Ok(());
    };
    if metadata.is_dir() {
        fs::remove_dir_all(path).map_err(|err| format!("{operation} {}: {err}", path.display()))
    } else {
        fs::remove_file(path).map_err(|err| format!("{operation} {}: {err}", path.display()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeltaInternalName {
    State,
    Package,
}

fn delta_internal_name(name: &str) -> Option<DeltaInternalName> {
    let key = portable_path_collision_key(name);
    let state_key = portable_path_collision_key(DELTA_STATE_DIR);
    let package_key = portable_path_collision_key(DELTA_PACKAGE_PREFIX);
    if key == state_key {
        Some(DeltaInternalName::State)
    } else if key.starts_with(&package_key) {
        Some(DeltaInternalName::Package)
    } else {
        None
    }
}

fn cli_delta_policy_is_content_only(policy: &MetadataPolicy) -> bool {
    !policy.preserve_unix_permissions
        && !policy.preserve_windows_attributes
        && !policy.preserve_extended_attributes
        && !policy.preserve_symlinks
        && !policy.preserve_timestamps
        && !policy.record_platform_metadata
}

fn cli_content_delta_enabled(no_delta: bool) -> bool {
    !no_delta && cli_delta_policy_is_content_only(&selected_cli_metadata_policy())
}

fn validate_user_transfer_namespace(source: &Path) -> Result<(), String> {
    validate_user_transfer_namespace_entry(source, true)
}

fn validate_user_transfer_namespace_entry(
    path: &Path,
    inspect_children: bool,
) -> Result<(), String> {
    if let Some(name) = path.file_name().and_then(|name| name.to_str())
        && delta_internal_name(name).is_some()
    {
        return Err(format!(
            "source contains reserved ATP delta namespace path: {}",
            path.display()
        ));
    }

    if !inspect_children {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("inspect source namespace {}: {err}", path.display()))?;
    if !metadata.is_dir()
        || path_is_link_or_reparse_sync(path)
            .map_err(|err| format!("inspect source namespace {}: {err}", path.display()))?
    {
        return Ok(());
    }

    let entries = fs::read_dir(path)
        .map_err(|err| format!("read source namespace {}: {err}", path.display()))?;
    for entry in entries {
        let entry = entry
            .map_err(|err| format!("read source namespace entry {}: {err}", path.display()))?;
        validate_user_transfer_namespace_entry(&entry.path(), true)?;
    }
    Ok(())
}

fn validate_canonical_hex_hash(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "{label} must be exactly 64 lowercase hexadecimal characters"
        ))
    }
}

fn canonical_delta_chunk_file_name(content_id_hex: &str) -> Result<String, String> {
    validate_canonical_hex_hash(content_id_hex, "delta chunk content id")?;
    Ok(format!("{content_id_hex}.chunk"))
}

fn canonical_delta_ops_file_name(
    target_content_id_hex: &str,
    base_content_id_hex: &str,
) -> Result<String, String> {
    validate_canonical_hex_hash(target_content_id_hex, "delta ops target content id")?;
    validate_canonical_hex_hash(base_content_id_hex, "delta ops base content id")?;
    Ok(format!(
        "{target_content_id_hex}-from-{}.subdelta.ops",
        &base_content_id_hex[..16]
    ))
}

fn require_canonical_delta_file_name(
    actual: &str,
    expected: &str,
    label: &str,
) -> Result<(), String> {
    if actual != expected {
        return Err(format!(
            "noncanonical {label} filename {actual:?}; expected {expected:?}"
        ));
    }
    validate_portable_relative_path(actual)
        .map_err(|_| format!("unsafe {label} filename: {actual:?}"))
}

fn validate_subdelta_output_size(ops: &[SubDeltaOp], expected_bytes: u64) -> Result<(), String> {
    if expected_bytes > u64::try_from(DELTA_MAX_CHUNK_BYTES).unwrap_or(u64::MAX) {
        return Err(format!(
            "delta sub-delta target size {expected_bytes} exceeds {} byte limit",
            DELTA_MAX_CHUNK_BYTES
        ));
    }
    let output_bytes = ops.iter().try_fold(0u64, |total, op| {
        let len = match op {
            SubDeltaOp::Copy { len, .. } => u64::from(*len),
            SubDeltaOp::Literal(bytes) => u64::try_from(bytes.len())
                .map_err(|_| "delta sub-delta literal length exceeds u64::MAX".to_string())?,
        };
        total
            .checked_add(len)
            .ok_or_else(|| "delta sub-delta output length overflow".to_string())
    })?;
    if output_bytes != expected_bytes {
        return Err(format!(
            "delta sub-delta output size mismatch: expected {expected_bytes}, ops produce {output_bytes}"
        ));
    }
    Ok(())
}

fn validate_subdelta_op_count_before_decode(bytes: &[u8]) -> Result<(), String> {
    let header_len = DELTA_SUBDELTA_OPS_MAGIC
        .len()
        .checked_add(8)
        .ok_or_else(|| "delta sub-delta header length overflow".to_string())?;
    let header = bytes
        .get(..header_len)
        .ok_or_else(|| "delta sub-delta op stream is truncated".to_string())?;
    if !header.starts_with(DELTA_SUBDELTA_OPS_MAGIC) {
        return Err("delta sub-delta op stream has invalid magic".to_string());
    }
    let count_bytes: [u8; 8] = header[DELTA_SUBDELTA_OPS_MAGIC.len()..]
        .try_into()
        .map_err(|_| "delta sub-delta op count is truncated".to_string())?;
    let op_count = usize::try_from(u64::from_be_bytes(count_bytes))
        .map_err(|_| "delta sub-delta op count exceeds usize::MAX".to_string())?;
    let max_op_count = bytes.len().saturating_sub(header_len) / DELTA_MIN_SUBDELTA_OP_BYTES;
    if op_count > max_op_count {
        return Err(format!(
            "delta sub-delta op count {op_count} exceeds the {max_op_count} entries possible in the remaining body"
        ));
    }
    Ok(())
}

fn prepare_delta_ssh_send(
    args: &SendArgs,
    remote: &RemoteTarget,
    remote_shell: RemoteShell,
) -> Result<Option<DeltaPreparedSend>, String> {
    let receiver_state = match fetch_remote_delta_state(args, remote, remote_shell) {
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
    if !cli_content_delta_enabled(args.no_delta) {
        return Ok(None);
    }
    if !args.allow_unauthenticated_delta_sidecar {
        if !args.no_delta
            && matches!(
                args.transport,
                Transport::Auto | Transport::Rq | Transport::Quic
            )
        {
            eprintln!(
                "[atp] delta planner: direct plaintext sidecar disabled; using full-object \
                 transfer (trusted labs may opt in with \
                 --allow-unauthenticated-delta-sidecar)"
            );
        }
        return Ok(None);
    }
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
    if !cli_content_delta_enabled(args.no_delta) {
        eprintln!("[atp] delta planner: metadata-preserving policy requires full-object transfer");
        return Ok(None);
    }
    let receiver_manifest = match receiver_state.manifest() {
        Ok(manifest) => manifest,
        Err(err) => {
            eprintln!(
                "[atp] delta planner: receiver state unreadable ({err}); using full-object transfer"
            );
            return Ok(None);
        }
    };
    let snapshot = match build_delta_source_snapshot(&args.source, args.max_bytes) {
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
    if cached_delta_match_requires_live_transfer(plan.mode) {
        eprintln!(
            "[atp] delta planner: cached receiver state matches, but no live receiver commit receipt was obtained; using full-object transfer"
        );
        return Ok(None);
    }
    match plan.mode {
        DeltaResyncMode::AlreadyInSync => unreachable!("handled above"),
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

fn cached_delta_match_requires_live_transfer(mode: DeltaResyncMode) -> bool {
    mode == DeltaResyncMode::AlreadyInSync
}

fn fetch_remote_delta_state(
    args: &SendArgs,
    remote: &RemoteTarget,
    remote_shell: RemoteShell,
) -> Result<Option<DeltaCliState>, String> {
    let argv = [
        args.remote_atp.clone(),
        "__delta-state-export".to_string(),
        remote.remote_path.clone(),
    ];
    let mut command = ssh_command(args, &remote.ssh_host);
    command
        .arg(remote_shell_command(remote_shell, &[], &argv)?)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|err| format!("fetch remote delta state via ssh: {err}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "fetch remote delta state stdout pipe unavailable".to_string())?;
    let body = match read_utf8_body_limited(&mut stdout, DELTA_MAX_METADATA_BYTES) {
        Ok(body) => body,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("fetch remote delta state via ssh: {err}"));
        }
    };
    let status = child
        .wait()
        .map_err(|err| format!("wait for remote delta state via ssh: {err}"))?;
    if !status.success() {
        return Ok(None);
    }
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    serde_json::from_str(trimmed)
        .map(Some)
        .map_err(|err| format!("parse remote delta state: {err}"))
}

fn read_utf8_body_limited(reader: &mut impl Read, max_bytes: usize) -> std::io::Result<String> {
    let read_limit = max_bytes.checked_add(1).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "body limit overflow")
    })?;
    let mut bytes = Vec::with_capacity(read_limit.min(8 * 1024));
    reader
        .take(u64::try_from(read_limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("JSON body exceeds {max_bytes} byte limit"),
        ));
    }
    String::from_utf8(bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    max_bytes: usize,
    deadline: Option<Instant>,
    deadline_operation: &'static str,
}

impl BoundedJsonWriter {
    fn new(max_bytes: usize) -> Self {
        Self::before(max_bytes, None, "encode JSON body")
    }

    fn before(
        max_bytes: usize,
        deadline: Option<Instant>,
        deadline_operation: &'static str,
    ) -> Self {
        Self {
            bytes: Vec::with_capacity(max_bytes.min(8 * 1024)),
            max_bytes,
            deadline,
            deadline_operation,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "{} exceeded the connection deadline",
                    self.deadline_operation
                ),
            ));
        }
        let next_len = self.bytes.len().checked_add(buf.len()).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "JSON body length overflow")
        })?;
        if next_len > self.max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("JSON body exceeds {} byte limit", self.max_bytes),
            ));
        }
        self.bytes.extend_from_slice(buf);
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "{} exceeded the connection deadline",
                    self.deadline_operation
                ),
            ));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "{} exceeded the connection deadline",
                    self.deadline_operation
                ),
            ));
        }
        Ok(())
    }
}

fn encode_json_body_limited<T: serde::Serialize>(
    value: &T,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut writer = BoundedJsonWriter::new(max_bytes);
    serde_json::to_writer(&mut writer, value).map_err(|err| format!("encode JSON body: {err}"))?;
    Ok(writer.into_inner())
}

fn encode_json_body_limited_before<T: serde::Serialize>(
    value: &T,
    max_bytes: usize,
    deadline: Instant,
    operation: &'static str,
) -> Result<Vec<u8>, String> {
    let mut writer = BoundedJsonWriter::before(max_bytes, Some(deadline), operation);
    serde_json::to_writer(&mut writer, value).map_err(|err| format!("encode JSON body: {err}"))?;
    Ok(writer.into_inner())
}

struct DeadlineSliceReader<'a> {
    remaining: &'a [u8],
    deadline: Instant,
    operation: &'static str,
}

impl Read for DeadlineSliceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("{} exceeded the connection deadline", self.operation),
            ));
        }
        let count = buf.len().min(self.remaining.len());
        buf[..count].copy_from_slice(&self.remaining[..count]);
        self.remaining = &self.remaining[count..];
        Ok(count)
    }
}

fn decode_json_body_before_deadline<T: for<'de> serde::Deserialize<'de>>(
    bytes: &[u8],
    deadline: Instant,
    operation: &'static str,
) -> Result<T, String> {
    let reader = BufReader::with_capacity(
        8 * 1024,
        DeadlineSliceReader {
            remaining: bytes,
            deadline,
            operation,
        },
    );
    let value = serde_json::from_reader(reader)
        .map_err(|err| format!("{operation} before deadline: {err}"))?;
    check_delta_sidecar_deadline(Some(deadline), operation)?;
    Ok(value)
}

fn check_delta_sidecar_deadline(deadline: Option<Instant>, operation: &str) -> Result<(), String> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        Err(format!("{operation} exceeded the connection deadline"))
    } else {
        Ok(())
    }
}

fn fetch_direct_delta_state(state_addr: SocketAddr) -> Result<Option<DeltaCliState>, String> {
    let mut stream = connect_direct_delta_state_sidecar(state_addr)?;
    let deadline =
        Instant::now() + Duration::from_millis(DIRECT_DELTA_SIDECAR_CONNECTION_DEADLINE_MS);
    let body =
        read_utf8_body_before_deadline(&mut stream, DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES, deadline)
            .map_err(|err| format!("read state: {err}"))?;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    decode_json_body_before_deadline(
        trimmed.as_bytes(),
        deadline,
        "parse direct receiver delta state",
    )
    .map(Some)
}

fn fetch_direct_subchunk_signatures(
    state_addr: SocketAddr,
    chunks: &[CasChunkRef],
) -> Result<Vec<DeltaChunkSignatureState>, String> {
    if chunks.is_empty() {
        return Ok(Vec::new());
    }

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
    let request_body = encode_json_body_limited(&request, DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES)
        .map_err(|err| format!("write subchunk signature request: {err}"))?;
    let mut stream = connect_direct_delta_state_sidecar(state_addr)?;
    let deadline =
        Instant::now() + Duration::from_millis(DIRECT_DELTA_SIDECAR_CONNECTION_DEADLINE_MS);
    write_all_tcp_before_deadline(&mut stream, &request_body, deadline)
        .map_err(|err| format!("write subchunk signature request: {err}"))?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|err| format!("shutdown subchunk signature request: {err}"))?;

    let body =
        read_utf8_body_before_deadline(&mut stream, DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES, deadline)
            .map_err(|err| format!("read subchunk signature response: {err}"))?;
    let response: DeltaSubchunkSignatureResponse = decode_json_body_before_deadline(
        body.trim().as_bytes(),
        deadline,
        "parse subchunk signature response",
    )?;
    if response.schema != DELTA_SUBCHUNK_SIGNATURE_RESPONSE_SCHEMA {
        return Err(format!(
            "unsupported subchunk signature response schema: {}",
            response.schema
        ));
    }
    Ok(response.signatures)
}

fn connect_direct_delta_state_sidecar(
    state_addr: SocketAddr,
) -> Result<std::net::TcpStream, String> {
    let attempt_timeout = Duration::from_millis(DIRECT_DELTA_SIDECAR_CONNECT_ATTEMPT_MS);
    let retry_sleep = Duration::from_millis(DIRECT_DELTA_SIDECAR_CONNECT_RETRY_SLEEP_MS);
    let deadline = Duration::from_millis(DIRECT_DELTA_SIDECAR_CONNECT_DEADLINE_MS);
    let start = Instant::now();
    loop {
        match std::net::TcpStream::connect_timeout(&state_addr, attempt_timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) if retryable_delta_state_connect_error(&err) && start.elapsed() < deadline => {
                thread::sleep(retry_sleep);
            }
            Err(err) => {
                return Err(format!(
                    "connect to receiver delta sidecar {state_addr} after {}ms: {err}",
                    start.elapsed().as_millis()
                ));
            }
        }
    }
}

fn retryable_delta_state_connect_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::AddrNotAvailable
    )
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
    let states_by_key = states
        .iter()
        .filter(|entry| {
            entry
                .signature
                .has_canonical_shape(entry.size_bytes, delta_subchunk::DEFAULT_SUBBLOCK_BYTES)
        })
        .map(|entry| ((entry.content_id_hex.as_str(), entry.size_bytes), entry))
        .collect::<BTreeMap<_, _>>();
    candidates
        .iter()
        .filter_map(|chunk| {
            let content_id_hex = chunk.content_id.to_hex();
            states_by_key
                .get(&(content_id_hex.as_str(), chunk.size_bytes))
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
    create_delta_dir(&chunk_dir, "create delta package chunk directory")?;
    let subchunk_dir = package_root.join(DELTA_SUBCHUNK_DIR);
    if !package.subdelta_chunks.is_empty() {
        create_delta_dir(&subchunk_dir, "create delta package subchunk directory")?;
    }

    let mut missing_chunks = Vec::with_capacity(package.whole_chunks.len());
    for whole in &package.whole_chunks {
        let chunk = &whole.chunk;
        let content_id_hex = chunk.content_id.to_hex();
        let file_name = canonical_delta_chunk_file_name(&content_id_hex)?;
        let path = chunk_dir.join(&file_name);
        let mut file = create_delta_file(&path, "create delta package chunk")?;
        write_delta_file(
            &mut file,
            &path,
            &whole.payload,
            "write delta package chunk",
        )?;
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
        let file_name =
            canonical_delta_ops_file_name(&target_content_id_hex, &base_content_id_hex)?;
        let path = subchunk_dir.join(&file_name);
        let mut file = create_delta_file(&path, "create delta subchunk ops")?;
        write_delta_file(
            &mut file,
            &path,
            &subdelta.encoded_ops,
            "write delta subchunk ops",
        )?;
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
    let mut file = create_delta_file(&manifest_path, "create delta package manifest")?;
    ensure_delta_path_chain(&manifest_path, "write delta package manifest")?;
    serde_json::to_writer(&mut file, &metadata).map_err(|err| {
        format!(
            "write delta package manifest {}: {err}",
            manifest_path.display()
        )
    })?;
    write_delta_file(
        &mut file,
        &manifest_path,
        b"\n",
        "finish delta package manifest",
    )?;

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
    let target_manifest_bytes = match (
        metadata.target_manifest_hex.as_deref(),
        metadata.target_manifest_b64.as_deref(),
    ) {
        (None, Some(encoded)) => STANDARD
            .decode(encoded)
            .map_err(|err| format!("decode delta package target manifest base64: {err}"))?,
        (Some(encoded), None) => hex::decode(encoded)
            .map_err(|err| format!("decode delta package target manifest: {err}"))?,
        (None, None) => return Err("delta package target manifest is missing".to_string()),
        (Some(_), Some(_)) => {
            return Err(
                "delta package target manifest must use exactly one canonical encoding".to_string(),
            );
        }
    };
    PersistentChunkManifest::from_canonical_bytes(&target_manifest_bytes)
        .map_err(|err| format!("decode delta package target manifest: {err}"))
}

fn create_unique_delta_package_root(object_sha256_hex: &str) -> Result<PathBuf, String> {
    let short = object_sha256_hex.get(..16).unwrap_or(object_sha256_hex);
    for attempt in 0..32u32 {
        let nonce = unique_micros();
        let path = env::temp_dir().join(format!("{DELTA_PACKAGE_PREFIX}{short}-{nonce}-{attempt}"));
        ensure_delta_path_chain(&path, "create delta package root")?;
        match fs::create_dir(&path) {
            Ok(()) => {
                require_delta_directory(&path, "create delta package root")?;
                return Ok(path);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
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

fn create_unique_delta_staging_root(
    state_dir: &Path,
    object_sha256_hex: &str,
) -> Result<PathBuf, String> {
    create_delta_dir_all(state_dir, "create delta state directory")?;
    for attempt in 0..32u32 {
        let path = state_dir.join(format!(
            "staging-{object_sha256_hex}-{}-{attempt}",
            unique_micros()
        ));
        ensure_delta_path_chain(&path, "create delta staging root")?;
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(format!(
                    "create delta staging root {}: {err}",
                    path.display()
                ));
            }
        }
    }
    Err("could not allocate a unique delta staging directory".to_string())
}

fn build_delta_source_snapshot(
    source: &Path,
    max_bytes: u64,
) -> Result<DeltaSourceSnapshot, String> {
    let files = collect_delta_tree_files(source, max_bytes).map_err(|error| error.to_string())?;
    build_delta_snapshot_from_files(files, max_bytes)
}

fn build_delta_dest_snapshot(
    dest: &Path,
    max_bytes: u64,
) -> Result<DeltaSourceSnapshot, DeltaSnapshotFailure> {
    let files = collect_delta_dest_tree_files(dest, max_bytes)?;
    build_delta_snapshot_from_files(files, max_bytes).map_err(DeltaSnapshotFailure::fatal)
}

fn build_delta_snapshot_from_files(
    files: Vec<DeltaTreeFile>,
    max_bytes: u64,
) -> Result<DeltaSourceSnapshot, String> {
    let logical_file_bytes = files.iter().try_fold(0u64, |total, file| {
        let len = u64::try_from(file.bytes.len())
            .map_err(|_| "delta source file length exceeds u64::MAX".to_string())?;
        total
            .checked_add(len)
            .ok_or_else(|| "delta source logical size exceeds u64::MAX".to_string())
    })?;
    if logical_file_bytes > max_bytes {
        return Err(format!(
            "delta source logical size {logical_file_bytes} exceeds --max-bytes {max_bytes}"
        ));
    }
    let object_bytes = encode_delta_tree_object(&files)?;
    let encoded_bytes = u64::try_from(object_bytes.len())
        .map_err(|_| "encoded delta object size exceeds u64::MAX".to_string())?;
    if encoded_bytes > max_bytes {
        return Err(format!(
            "encoded delta object size {encoded_bytes} exceeds --max-bytes {max_bytes}"
        ));
    }
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

/// FastCDC-style gear hash: `hash = (hash << 1) + T[byte]`. No explicit
/// window or eviction — the shift ages old bytes out of any fixed bit range
/// naturally, and the ADD's carry propagation mixes across bit positions
/// (matching `net::atp::chunk::dedupe::RollingHash`). The previous
/// rotate-XOR variant with an explicit 64-byte window was GF(2)-linear and
/// rotation-periodic, so 64-periodic or low-entropy input collapsed its hash
/// orbit and boundaries stopped firing entirely (br-asupersync-iz269u).
struct DeltaTreeRollingGear {
    hash: u64,
}

impl DeltaTreeRollingGear {
    fn new() -> Self {
        Self { hash: 0 }
    }

    fn update(&mut self, byte: u8) {
        self.hash = (self.hash << 1).wrapping_add(delta_tree_gear_value(byte));
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

fn delta_snapshot_metadata(
    path: &Path,
    operation: &str,
) -> Result<fs::Metadata, DeltaSnapshotFailure> {
    match delta_link_or_reparse_prefix(path, operation) {
        Ok(Some(prefix)) => Err(DeltaSnapshotFailure::unsupported(format!(
            "{operation} is unsupported through symlink or reparse-point prefix {}",
            prefix.display()
        ))),
        Ok(None) => fs::symlink_metadata(path).map_err(|err| {
            DeltaSnapshotFailure::fatal(format!(
                "read metadata {} for {operation}: {err}",
                path.display()
            ))
        }),
        Err(error) => Err(DeltaSnapshotFailure::fatal(error)),
    }
}

fn collect_delta_dest_tree_files(
    dest: &Path,
    max_bytes: u64,
) -> Result<Vec<DeltaTreeFile>, DeltaSnapshotFailure> {
    let metadata = delta_snapshot_metadata(dest, "snapshot delta destination")?;
    if !metadata.is_dir() {
        return Err(DeltaSnapshotFailure::unsupported(format!(
            "delta destination is not a directory: {}",
            dest.display()
        )));
    }

    let mut files = Vec::new();
    let mut budget = DeltaSnapshotBudget::new(max_bytes);
    ensure_delta_path_chain(dest, "read delta destination directory")
        .map_err(DeltaSnapshotFailure::fatal)?;
    let mut entries = fs::read_dir(dest)
        .map_err(|err| {
            DeltaSnapshotFailure::fatal(format!("read directory {}: {err}", dest.display()))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            DeltaSnapshotFailure::fatal(format!("read directory entry {}: {err}", dest.display()))
        })?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let name = entry.file_name().into_string().map_err(|_| {
            DeltaSnapshotFailure::unsupported(format!(
                "non-UTF-8 path under {} is not delta-packable",
                dest.display()
            ))
        })?;
        let path = entry.path();
        let metadata = delta_snapshot_metadata(&path, "snapshot delta destination entry")?;
        if let Some(kind) = delta_internal_name(&name) {
            let canonical = match kind {
                DeltaInternalName::State => name == DELTA_STATE_DIR,
                DeltaInternalName::Package => name.starts_with(DELTA_PACKAGE_PREFIX),
            };
            if !canonical {
                return Err(DeltaSnapshotFailure::fatal(format!(
                    "noncanonical reserved delta path under {}: {name:?}",
                    dest.display()
                )));
            }
            if !metadata.is_dir() {
                return Err(DeltaSnapshotFailure::fatal(format!(
                    "reserved delta path is not a directory: {}",
                    path.display()
                )));
            }
            continue;
        }
        validate_delta_rel_path(&name).map_err(DeltaSnapshotFailure::fatal)?;
        if metadata.is_dir() {
            collect_delta_dir(&path, &name, &mut files, &mut budget)?;
        } else if metadata.is_file() {
            let bytes = budget.read_file(&path)?;
            files.push(DeltaTreeFile {
                rel_path: name,
                bytes,
            });
        } else {
            return Err(DeltaSnapshotFailure::unsupported(format!(
                "unsupported metadata in delta destination: {}",
                path.display()
            )));
        }
    }

    if files.is_empty() {
        return Err(DeltaSnapshotFailure::unsupported(
            "empty directory trees use full-object transfer",
        ));
    }
    Ok(files)
}

fn collect_delta_tree_files(
    source: &Path,
    max_bytes: u64,
) -> Result<Vec<DeltaTreeFile>, DeltaSnapshotFailure> {
    let metadata = delta_snapshot_metadata(source, "snapshot delta source")?;
    let root_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            DeltaSnapshotFailure::unsupported(format!(
                "delta source has no UTF-8 file name: {}",
                source.display()
            ))
        })?;
    validate_delta_rel_path(root_name).map_err(DeltaSnapshotFailure::fatal)?;

    let mut files = Vec::new();
    let mut budget = DeltaSnapshotBudget::new(max_bytes);
    if metadata.is_file() {
        let bytes = budget.read_file(source)?;
        files.push(DeltaTreeFile {
            rel_path: root_name.to_string(),
            bytes,
        });
        return Ok(files);
    }
    if metadata.is_dir() {
        collect_delta_dir(source, root_name, &mut files, &mut budget)?;
        if files.is_empty() {
            return Err(DeltaSnapshotFailure::unsupported(
                "empty directory trees use full-object transfer",
            ));
        }
        return Ok(files);
    }

    Err(DeltaSnapshotFailure::unsupported(format!(
        "unsupported source type for transparent delta: {}",
        source.display()
    )))
}

fn collect_delta_dir(
    dir: &Path,
    rel_prefix: &str,
    files: &mut Vec<DeltaTreeFile>,
    budget: &mut DeltaSnapshotBudget,
) -> Result<(), DeltaSnapshotFailure> {
    delta_snapshot_metadata(dir, "read delta directory")?;
    let mut entries = fs::read_dir(dir)
        .map_err(|err| {
            DeltaSnapshotFailure::fatal(format!("read directory {}: {err}", dir.display()))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            DeltaSnapshotFailure::fatal(format!("read directory entry {}: {err}", dir.display()))
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    if entries.is_empty() {
        return Err(DeltaSnapshotFailure::unsupported(format!(
            "empty directory {} requires full-object transfer",
            dir.display()
        )));
    }

    for entry in entries {
        let name = entry.file_name().into_string().map_err(|_| {
            DeltaSnapshotFailure::unsupported(format!(
                "non-UTF-8 path under {} is not delta-packable",
                dir.display()
            ))
        })?;
        let rel_path = format!("{rel_prefix}/{name}");
        validate_delta_rel_path(&rel_path).map_err(DeltaSnapshotFailure::fatal)?;
        let path = entry.path();
        let metadata = delta_snapshot_metadata(&path, "snapshot delta tree entry")?;
        if metadata.is_dir() {
            collect_delta_dir(&path, &rel_path, files, budget)?;
        } else if metadata.is_file() {
            let bytes = budget.read_file(&path)?;
            files.push(DeltaTreeFile { rel_path, bytes });
        } else {
            return Err(DeltaSnapshotFailure::unsupported(format!(
                "unsupported source type for transparent delta: {}",
                path.display()
            )));
        }
    }

    Ok(())
}

fn encode_delta_tree_object(files: &[DeltaTreeFile]) -> Result<Vec<u8>, String> {
    validate_distinct_delta_paths(files.iter().map(|file| file.rel_path.as_str()))?;
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
    if validate_portable_relative_path(rel_path).is_err()
        || rel_path
            .split('/')
            .any(|component| delta_internal_name(component).is_some())
    {
        return Err(format!("unsafe delta relative path: {rel_path}"));
    }
    Ok(())
}

fn validate_distinct_delta_paths<'a>(
    paths: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    validate_portable_path_set(paths)
        .map_err(|error| format!("unsafe or colliding delta path set: {error}"))
}

fn unique_micros() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
}

fn handle_post_receive_delta(dest: &Path, enabled: bool, max_bytes: u64) -> Result<(), String> {
    if !enabled {
        return Ok(());
    }
    let applied = apply_delta_packages(dest, max_bytes)?;
    finish_delta_refresh(applied, refresh_delta_state(dest, max_bytes))
}

fn finish_delta_refresh(
    applied: usize,
    refresh: Result<DeltaCliState, DeltaSnapshotFailure>,
) -> Result<(), String> {
    match refresh {
        Ok(_) => Ok(()),
        Err(DeltaSnapshotFailure::UnsupportedCapability(reason)) if applied == 0 => {
            eprintln!(
                "[atp] delta refresh skipped ({reason}); future sends will use full-object transfer"
            );
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn apply_delta_packages(dest: &Path, max_bytes: u64) -> Result<usize, String> {
    let Some(metadata) = delta_path_metadata(dest, "scan delta packages")? else {
        return Ok(0);
    };
    if !metadata.is_dir() {
        return Ok(0);
    }
    ensure_delta_path_chain(dest, "read delta package directory")?;
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
        let path = entry.path();
        let Some(internal) = delta_internal_name(&name) else {
            continue;
        };
        match internal {
            DeltaInternalName::State => {
                if name != DELTA_STATE_DIR {
                    return Err(format!(
                        "noncanonical reserved delta state path under {}: {name:?}",
                        dest.display()
                    ));
                }
                continue;
            }
            DeltaInternalName::Package if !name.starts_with(DELTA_PACKAGE_PREFIX) => {
                return Err(format!(
                    "noncanonical reserved delta package path under {}: {name:?}",
                    dest.display()
                ));
            }
            DeltaInternalName::Package => {}
        }
        let package_metadata = delta_path_metadata(&path, "inspect delta package root")?
            .ok_or_else(|| format!("delta package disappeared: {}", path.display()))?;
        if !package_metadata.is_dir() {
            return Err(format!(
                "reserved delta package path is not a directory: {}",
                path.display()
            ));
        }
        let receipt = path.join(".applied");
        match delta_path_metadata(&receipt, "inspect delta package receipt")? {
            Some(metadata) if metadata.is_file() => {
                remove_delta_path_if_exists(&path, "remove applied delta package")?;
            }
            Some(_) => {
                return Err(format!(
                    "delta package receipt is not a regular file: {}",
                    receipt.display()
                ));
            }
            None => {
                apply_delta_package(dest, &path, max_bytes)?;
                let mut file = create_delta_file(&receipt, "create delta package receipt")?;
                let receipt_body = unique_micros().to_string();
                write_delta_file(
                    &mut file,
                    &receipt,
                    receipt_body.as_bytes(),
                    "write delta package receipt",
                )?;
                applied += 1;
                remove_delta_path_if_exists(&path, "remove applied delta package")?;
            }
        }
    }
    Ok(applied)
}

fn apply_delta_package(dest: &Path, package_root: &Path, max_bytes: u64) -> Result<(), String> {
    require_delta_directory(dest, "apply delta package")?;
    require_delta_directory(package_root, "apply delta package")?;
    let metadata_path = package_root.join(DELTA_PACKAGE_FILE);
    let metadata_bytes = read_delta_file_bounded_before(
        &metadata_path,
        DELTA_MAX_METADATA_BYTES,
        None,
        "read delta package metadata",
    )?;
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
    enforce_transfer_size(
        "delta target encoded object",
        target_manifest.total_size_bytes,
        max_bytes,
    )?;
    validate_canonical_hex_hash(&metadata.object_sha256_hex, "delta package object sha256")?;

    let mut package_paths = Vec::new();
    let mut carried_targets = BTreeMap::<String, &'static str>::new();
    for chunk in &metadata.missing_chunks {
        let expected = canonical_delta_chunk_file_name(&chunk.content_id_hex)?;
        require_canonical_delta_file_name(&chunk.file_name, &expected, "delta chunk")?;
        if !target_manifest.chunks.iter().any(|target| {
            target.content_id.to_hex() == chunk.content_id_hex
                && target.size_bytes == chunk.size_bytes
        }) {
            return Err(format!(
                "delta package chunk {}:{} is absent from the target manifest",
                chunk.content_id_hex, chunk.size_bytes
            ));
        }
        if let Some(existing) = carried_targets.insert(chunk.content_id_hex.clone(), "whole chunk")
        {
            return Err(format!(
                "delta package carries target {} more than once ({existing} and whole chunk)",
                chunk.content_id_hex
            ));
        }
        package_paths.push(format!("{DELTA_CHUNK_DIR}/{expected}"));
    }
    for subdelta in &metadata.subdelta_chunks {
        validate_canonical_hex_hash(
            &subdelta.target_sha256_hex,
            "delta package sub-delta target sha256",
        )?;
        let expected = canonical_delta_ops_file_name(
            &subdelta.target_content_id_hex,
            &subdelta.base_content_id_hex,
        )?;
        require_canonical_delta_file_name(
            &subdelta.ops_file_name,
            &expected,
            "delta sub-delta ops",
        )?;
        if let Some(existing) =
            carried_targets.insert(subdelta.target_content_id_hex.clone(), "sub-delta")
        {
            return Err(format!(
                "delta package carries target {} more than once ({existing} and sub-delta)",
                subdelta.target_content_id_hex
            ));
        }
        package_paths.push(format!("{DELTA_SUBCHUNK_DIR}/{expected}"));
    }
    validate_distinct_delta_paths(package_paths.iter().map(String::as_str))?;

    let receiver_state = read_local_delta_state(dest)?.ok_or_else(|| {
        "delta package received but receiver has no prior delta state".to_string()
    })?;
    let receiver_manifest = receiver_state.manifest()?;
    enforce_transfer_size(
        "delta receiver base object",
        receiver_manifest.total_size_bytes,
        max_bytes,
    )?;
    let mut store = load_delta_store_from_state(dest, &receiver_manifest)?;

    let chunk_dir = package_root.join(DELTA_CHUNK_DIR);
    if !metadata.missing_chunks.is_empty() {
        require_delta_directory(&chunk_dir, "read delta package chunks")?;
    }
    for chunk in &metadata.missing_chunks {
        let path = chunk_dir.join(&chunk.file_name);
        let bytes = read_delta_file_exact_before(
            &path,
            chunk.size_bytes,
            DELTA_MAX_CHUNK_BYTES,
            None,
            "read delta package chunk",
        )?;
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
    if !metadata.subdelta_chunks.is_empty() {
        require_delta_directory(&subchunk_dir, "read delta package sub-delta ops")?;
    }
    for subdelta in &metadata.subdelta_chunks {
        let target_sha256 = decode_sha256_hex(
            &subdelta.target_sha256_hex,
            "delta package sub-delta target sha256",
        )?;
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
        let encoded_ops = read_delta_file_exact_before(
            &ops_path,
            subdelta.ops_wire_bytes,
            DELTA_MAX_SUBDELTA_OPS_BYTES,
            None,
            "read delta package sub-delta ops",
        )?;
        validate_subdelta_op_count_before_decode(&encoded_ops)?;
        let ops = decode_subdelta_ops(&encoded_ops)
            .map_err(|err| format!("parse delta package sub-delta ops: {err}"))?;
        validate_subdelta_output_size(&ops, target_chunk.size_bytes)?;
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
        validate_canonical_hex_hash(
            &repeated.target_content_id_hex,
            "delta package repeated target content id",
        )?;
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
    let object_bytes = reconstruct_delta_object_bytes(&target_manifest, &store, max_bytes)?;
    let object_sha256_hex = hex::encode(Sha256::digest(&object_bytes));
    if object_sha256_hex != metadata.object_sha256_hex {
        return Err(format!(
            "delta package object sha256 mismatch: expected {}, got {}",
            metadata.object_sha256_hex, object_sha256_hex
        ));
    }
    let files = decode_delta_tree_object(&object_bytes, max_bytes)?;
    commit_delta_tree_files(dest, &files, &object_sha256_hex, max_bytes)
}

fn refresh_delta_state(dest: &Path, max_bytes: u64) -> Result<DeltaCliState, DeltaSnapshotFailure> {
    let snapshot = build_delta_dest_snapshot(dest, max_bytes)?;
    let state_dir = dest.join(DELTA_STATE_DIR);
    let chunk_dir = state_dir.join(DELTA_CHUNK_DIR);
    create_delta_dir_all(&chunk_dir, "create delta state directory")
        .map_err(DeltaSnapshotFailure::fatal)?;

    for (content_id_hex, payload) in &snapshot.chunks_by_content {
        let file_name =
            canonical_delta_chunk_file_name(content_id_hex).map_err(DeltaSnapshotFailure::fatal)?;
        let path = chunk_dir.join(file_name);
        if delta_path_metadata(&path, "inspect delta state chunk")
            .map_err(DeltaSnapshotFailure::fatal)?
            .is_some()
        {
            let declared_bytes = u64::try_from(payload.len()).map_err(|_| {
                DeltaSnapshotFailure::fatal("delta state chunk size exceeds u64::MAX")
            })?;
            let existing = read_delta_file_exact_before(
                &path,
                declared_bytes,
                DELTA_MAX_CHUNK_BYTES,
                None,
                "read existing delta state chunk",
            )
            .map_err(DeltaSnapshotFailure::fatal)?;
            if existing.as_slice() != payload.as_slice()
                || ContentId::from_bytes(&existing).to_hex() != *content_id_hex
            {
                return Err(DeltaSnapshotFailure::fatal(format!(
                    "existing delta state chunk does not match {}",
                    path.display()
                )));
            }
        } else {
            let mut file = create_delta_file(&path, "create delta state chunk")
                .map_err(DeltaSnapshotFailure::fatal)?;
            write_delta_file(&mut file, &path, payload, "write delta state chunk")
                .map_err(DeltaSnapshotFailure::fatal)?;
        }
    }

    let state = delta_cli_state_from_snapshot(&snapshot).map_err(DeltaSnapshotFailure::fatal)?;
    let path = state_dir.join(DELTA_STATE_FILE);
    let mut file =
        create_delta_file(&path, "create delta state").map_err(DeltaSnapshotFailure::fatal)?;
    ensure_delta_path_chain(&path, "write delta state").map_err(DeltaSnapshotFailure::fatal)?;
    serde_json::to_writer_pretty(&mut file, &state).map_err(|err| {
        DeltaSnapshotFailure::fatal(format!("write delta state {}: {err}", path.display()))
    })?;
    write_delta_file(&mut file, &path, b"\n", "finish delta state")
        .map_err(DeltaSnapshotFailure::fatal)?;
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

fn read_file_limited_before_deadline(
    file: &mut fs::File,
    max_bytes: usize,
    deadline: Option<Instant>,
    operation: &str,
) -> Result<Vec<u8>, String> {
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| format!("{operation} byte limit overflow"))?;
    let metadata_len = file
        .metadata()
        .map_err(|err| format!("inspect file before {operation}: {err}"))?
        .len();
    if metadata_len > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(format!("{operation} exceeds {max_bytes} byte limit"));
    }

    let mut bytes = Vec::with_capacity(read_limit.min(8 * 1024));
    let mut chunk = [0u8; 8 * 1024];
    loop {
        check_delta_sidecar_deadline(deadline, operation)?;
        let remaining = read_limit.saturating_sub(bytes.len());
        if remaining == 0 {
            return Err(format!("{operation} exceeds {max_bytes} byte limit"));
        }
        let chunk_limit = remaining.min(chunk.len());
        let count = file
            .read(&mut chunk[..chunk_limit])
            .map_err(|err| format!("{operation}: {err}"))?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > max_bytes {
            return Err(format!("{operation} exceeds {max_bytes} byte limit"));
        }
    }
    check_delta_sidecar_deadline(deadline, operation)?;
    Ok(bytes)
}

fn read_local_delta_state_before(
    dest: &Path,
    deadline: Option<Instant>,
) -> Result<Option<DeltaCliState>, String> {
    let path = dest.join(DELTA_STATE_DIR).join(DELTA_STATE_FILE);
    if delta_path_metadata(&path, "inspect delta state")?.is_none() {
        return Ok(None);
    }
    let bytes = read_delta_file_bounded_before(
        &path,
        DELTA_MAX_METADATA_BYTES,
        deadline,
        "read delta state",
    )?;
    let state = if let Some(deadline) = deadline {
        decode_json_body_before_deadline(&bytes, deadline, "parse delta state")
    } else {
        serde_json::from_slice(&bytes).map_err(|err| format!("parse delta state: {err}"))
    }
    .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(Some(state))
}

fn read_local_delta_state(dest: &Path) -> Result<Option<DeltaCliState>, String> {
    read_local_delta_state_before(dest, None)
}

fn export_delta_state(dest: &Path) -> Result<(), String> {
    let Some(state) = read_local_delta_state(dest)? else {
        return Ok(());
    };
    let body = encode_json_body_limited(&state, DELTA_MAX_METADATA_BYTES)?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&body)
        .map_err(|err| format!("write delta state export: {err}"))?;
    stdout
        .write_all(b"\n")
        .map_err(|err| format!("finish delta state export: {err}"))
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
    let deadline =
        Instant::now() + Duration::from_millis(DIRECT_DELTA_SIDECAR_CONNECTION_DEADLINE_MS);
    match read_delta_state_sidecar_request(&mut stream, deadline) {
        Ok(Some(body)) => {
            if let Err(err) =
                serve_delta_subchunk_signature_request(&mut stream, dest, &body, deadline)
            {
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

    match read_local_delta_state_before(dest, Some(deadline)) {
        Ok(Some(state)) => {
            let body = match encode_json_body_limited_before(
                &state,
                DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES,
                deadline,
                "encode delta state response",
            ) {
                Ok(body) => body,
                Err(err) => {
                    eprintln!("atp: delta state sidecar response rejected: {err}");
                    return;
                }
            };
            if let Err(err) = write_all_tcp_before_deadline(&mut stream, &body, deadline) {
                eprintln!("atp: delta state sidecar finish failed: {err}");
            }
        }
        Ok(None) => {}
        Err(err) => eprintln!("atp: delta state sidecar could not read state: {err}"),
    }
}

fn read_delta_state_sidecar_request(
    stream: &mut std::net::TcpStream,
    deadline: Instant,
) -> std::io::Result<Option<String>> {
    let first_byte_timeout = deadline
        .checked_duration_since(Instant::now())
        .unwrap_or_default()
        .min(Duration::from_millis(
            DIRECT_DELTA_SIDECAR_FIRST_BYTE_TIMEOUT_MS,
        ));
    if first_byte_timeout.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "delta sidecar connection deadline elapsed",
        ));
    }
    stream.set_read_timeout(Some(first_byte_timeout))?;

    let mut bytes = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    match stream.read(&mut chunk) {
        Ok(0) => return Ok(None),
        Ok(read) => bytes.extend_from_slice(&chunk[..read]),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            return Ok(None);
        }
        Err(err) => return Err(err),
    }

    loop {
        if bytes.len() > DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "JSON body exceeds {} byte limit",
                    DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES
                ),
            ));
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "delta sidecar request exceeded the absolute connection deadline",
                )
            })?;
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => bytes.extend_from_slice(&chunk[..read]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "delta sidecar request exceeded the absolute connection deadline",
                ));
            }
            Err(err) => return Err(err),
        }
    }

    if bytes.len() > DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "JSON body exceeds {} byte limit",
                DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES
            ),
        ));
    }
    let body = String::from_utf8(bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let trimmed = body.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn read_utf8_body_before_deadline(
    stream: &mut std::net::TcpStream,
    max_bytes: usize,
    deadline: Instant,
) -> std::io::Result<String> {
    stream.set_nonblocking(true)?;
    let read_limit = max_bytes.checked_add(1).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "body limit overflow")
    })?;
    let mut bytes = Vec::with_capacity(read_limit.min(8 * 1024));
    let mut chunk = [0u8; 8 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "delta sidecar read exceeded the absolute connection deadline",
            ));
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                let remaining = read_limit.saturating_sub(bytes.len());
                bytes.extend_from_slice(&chunk[..count.min(remaining)]);
                if bytes.len() > max_bytes || count > remaining {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("JSON body exceeds {max_bytes} byte limit"),
                    ));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or_default();
                thread::sleep(remaining.min(Duration::from_millis(1)));
            }
            Err(err) => return Err(err),
        }
    }
    String::from_utf8(bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

fn write_all_tcp_before_deadline(
    stream: &mut std::net::TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> std::io::Result<()> {
    stream.set_nonblocking(true)?;
    let mut written = 0;
    while written < bytes.len() {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "delta sidecar response exceeded the absolute connection deadline",
            ));
        }
        match stream.write(&bytes[written..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "delta sidecar response socket accepted zero bytes",
                ));
            }
            Ok(count) => written += count,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or_default();
                thread::sleep(remaining.min(Duration::from_millis(1)));
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn serve_delta_subchunk_signature_request(
    stream: &mut std::net::TcpStream,
    dest: &Path,
    body: &str,
    deadline: Instant,
) -> Result<(), String> {
    let request: DeltaSubchunkSignatureRequest = decode_json_body_before_deadline(
        body.as_bytes(),
        deadline,
        "parse subchunk signature request",
    )?;
    let response = build_delta_subchunk_signature_response_before(dest, request, Some(deadline))?;
    let response_body = encode_json_body_limited_before(
        &response,
        DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES,
        deadline,
        "encode subchunk signature response",
    )
    .map_err(|err| format!("write subchunk signature response: {err}"))?;
    write_all_tcp_before_deadline(stream, &response_body, deadline)
        .map_err(|err| format!("finish subchunk signature response: {err}"))
}

#[cfg(test)]
fn build_delta_subchunk_signature_response(
    dest: &Path,
    request: DeltaSubchunkSignatureRequest,
) -> Result<DeltaSubchunkSignatureResponse, String> {
    build_delta_subchunk_signature_response_before(dest, request, None)
}

fn build_delta_subchunk_signature_response_before(
    dest: &Path,
    request: DeltaSubchunkSignatureRequest,
    deadline: Option<Instant>,
) -> Result<DeltaSubchunkSignatureResponse, String> {
    if request.schema != DELTA_SUBCHUNK_SIGNATURE_REQUEST_SCHEMA {
        return Err(format!(
            "unsupported subchunk signature request schema: {}",
            request.schema
        ));
    }
    if request.chunks.len() > DIRECT_DELTA_SIDECAR_MAX_REQUEST_CHUNKS {
        return Err(format!(
            "subchunk signature request has {} chunks; maximum is {}",
            request.chunks.len(),
            DIRECT_DELTA_SIDECAR_MAX_REQUEST_CHUNKS
        ));
    }
    check_delta_sidecar_deadline(deadline, "load delta state")?;
    let receiver_state = read_local_delta_state_before(dest, deadline)?.ok_or_else(|| {
        "subchunk signature request received but receiver has no delta state".to_string()
    })?;
    check_delta_sidecar_deadline(deadline, "decode delta state manifest")?;
    let receiver_manifest = receiver_state.manifest()?;
    check_delta_sidecar_deadline(deadline, "decode delta state manifest")?;
    let mut manifest_by_key = BTreeMap::new();
    for (index, chunk) in receiver_manifest.chunks.iter().enumerate() {
        if index % 1024 == 0 {
            check_delta_sidecar_deadline(deadline, "index delta state manifest")?;
        }
        manifest_by_key.insert((chunk.content_id.to_hex(), chunk.size_bytes), chunk);
    }
    check_delta_sidecar_deadline(deadline, "index delta state manifest")?;

    let mut signatures = Vec::new();
    let mut seen = BTreeSet::<(String, u64)>::new();
    let mut signature_blocks = 0usize;
    let mut signature_json_bytes = 0usize;
    for requested in request.chunks {
        check_delta_sidecar_deadline(deadline, "build subchunk signature response")?;
        validate_canonical_hex_hash(
            &requested.content_id_hex,
            "subchunk signature request content id",
        )?;
        let key = (requested.content_id_hex, requested.size_bytes);
        if !seen.insert(key.clone()) {
            continue;
        }
        let Some(chunk) = manifest_by_key.get(&key).copied() else {
            continue;
        };
        let block_size = u64::try_from(delta_subchunk::DEFAULT_SUBBLOCK_BYTES)
            .map_err(|_| "delta subchunk block size exceeds u64::MAX".to_string())?;
        let signature_block_count = usize::try_from(chunk.size_bytes / block_size)
            .map_err(|_| "subchunk signature block count exceeds usize::MAX".to_string())?;
        charge_delta_signature_blocks(
            &mut signature_blocks,
            signature_block_count,
            DIRECT_DELTA_SIDECAR_MAX_SIGNATURE_BLOCKS,
        )?;
        let payload = read_delta_state_chunk_before(dest, chunk, deadline)?;
        let payload_len = u64::try_from(payload.len())
            .map_err(|_| "delta state chunk payload length exceeds u64::MAX".to_string())?;
        if payload_len != chunk.size_bytes || ContentId::from_bytes(&payload) != chunk.content_id {
            return Err(format!(
                "delta state source chunk {} does not match manifest",
                key.0
            ));
        }
        let state = DeltaChunkSignatureState {
            content_id_hex: key.0,
            size_bytes: key.1,
            signature: delta_subchunk::signature(&payload, delta_subchunk::DEFAULT_SUBBLOCK_BYTES),
        };
        let encoded_state = if let Some(deadline) = deadline {
            encode_json_body_limited_before(
                &state,
                DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES,
                deadline,
                "encode subchunk signature entry",
            )?
        } else {
            encode_json_body_limited(&state, DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES)?
        };
        signature_json_bytes = signature_json_bytes
            .checked_add(encoded_state.len())
            .and_then(|bytes| bytes.checked_add(usize::from(!signatures.is_empty())))
            .ok_or_else(|| "subchunk signature response size overflow".to_string())?;
        if signature_json_bytes
            > DIRECT_DELTA_SIDECAR_MAX_JSON_BYTES
                .saturating_sub(DIRECT_DELTA_SIDECAR_RESPONSE_OVERHEAD_BYTES)
        {
            return Err("subchunk signature response exceeds JSON work budget".to_string());
        }
        signatures.push(state);
    }

    Ok(DeltaSubchunkSignatureResponse {
        schema: DELTA_SUBCHUNK_SIGNATURE_RESPONSE_SCHEMA.to_string(),
        signatures,
    })
}

fn charge_delta_signature_blocks(
    used: &mut usize,
    additional: usize,
    limit: usize,
) -> Result<(), String> {
    let next = used
        .checked_add(additional)
        .ok_or_else(|| "subchunk signature block budget overflow".to_string())?;
    if next > limit {
        return Err(format!(
            "subchunk signature response exceeds {limit} block work limit"
        ));
    }
    *used = next;
    Ok(())
}

fn read_delta_state_chunk_before(
    dest: &Path,
    chunk: &CasChunkRef,
    deadline: Option<Instant>,
) -> Result<Vec<u8>, String> {
    let content_id_hex = chunk.content_id.to_hex();
    let path = dest
        .join(DELTA_STATE_DIR)
        .join(DELTA_CHUNK_DIR)
        .join(format!("{content_id_hex}.chunk"));
    let expected_len = usize::try_from(chunk.size_bytes)
        .map_err(|_| format!("delta state chunk {} exceeds usize::MAX", path.display()))?;
    if expected_len > DELTA_TREE_OBJECT_MAX_CHUNK_BYTES {
        return Err(format!(
            "delta state chunk {} exceeds {} byte chunk limit",
            path.display(),
            DELTA_TREE_OBJECT_MAX_CHUNK_BYTES
        ));
    }
    let bytes = read_delta_file_exact_before(
        &path,
        chunk.size_bytes,
        DELTA_MAX_CHUNK_BYTES,
        deadline,
        "read delta state chunk",
    )?;
    if ContentId::from_bytes(&bytes) != chunk.content_id {
        return Err(format!(
            "delta state chunk {} does not match manifest",
            path.display()
        ));
    }
    check_delta_sidecar_deadline(deadline, "verify delta state chunk")?;
    Ok(bytes)
}

fn load_delta_store_from_state(
    dest: &Path,
    manifest: &PersistentChunkManifest,
) -> Result<DeltaChunkStore, String> {
    let chunk_dir = dest.join(DELTA_STATE_DIR).join(DELTA_CHUNK_DIR);
    let mut store = DeltaChunkStore::new();
    let mut loaded = BTreeSet::<String>::new();
    for chunk in &manifest.chunks {
        let content_id_hex = chunk.content_id.to_hex();
        if !loaded.insert(content_id_hex.clone()) {
            continue;
        }
        let path = chunk_dir.join(format!("{content_id_hex}.chunk"));
        let bytes = read_delta_file_exact_before(
            &path,
            chunk.size_bytes,
            DELTA_MAX_CHUNK_BYTES,
            None,
            "read delta state chunk",
        )?;
        if ContentId::from_bytes(&bytes) != chunk.content_id {
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
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    if manifest.total_size_bytes > max_bytes {
        return Err(format!(
            "delta object size {} exceeds {} byte limit",
            manifest.total_size_bytes, max_bytes
        ));
    }
    let capacity = usize::try_from(manifest.total_size_bytes)
        .map_err(|_| "delta object exceeds addressable memory on this host".to_string())?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|err| format!("reserve delta object buffer: {err}"))?;
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

fn decode_delta_tree_object(bytes: &[u8], max_bytes: u64) -> Result<Vec<DeltaTreeFile>, String> {
    let encoded_bytes = u64::try_from(bytes.len())
        .map_err(|_| "encoded delta object size exceeds u64::MAX".to_string())?;
    if encoded_bytes > max_bytes {
        return Err(format!(
            "encoded delta object size {encoded_bytes} exceeds {max_bytes} byte limit"
        ));
    }
    let mut reader = DeltaObjectReader::new(bytes);
    reader.expect_magic(DELTA_TREE_OBJECT_MAGIC)?;
    let file_count = reader.read_u64()?;
    let file_count = usize::try_from(file_count)
        .map_err(|_| "delta object file count exceeds usize::MAX".to_string())?;
    if file_count == 0 {
        return Err("empty directory delta objects must use full-object transfer".to_string());
    }
    if file_count > DELTA_MAX_FILE_COUNT {
        return Err(format!(
            "delta object file count {file_count} exceeds {DELTA_MAX_FILE_COUNT} file limit"
        ));
    }
    let entry_bytes = reader
        .remaining_len()
        .checked_sub(8)
        .ok_or_else(|| "delta object is missing its payload count".to_string())?;
    let max_file_count = entry_bytes / DELTA_MIN_FILE_ENTRY_BYTES;
    if file_count > max_file_count {
        return Err(format!(
            "delta object file count {file_count} exceeds the {max_file_count} entries possible in the remaining body"
        ));
    }
    let mut entries = Vec::new();
    entries
        .try_reserve(file_count)
        .map_err(|err| format!("reserve delta object file entries: {err}"))?;
    let mut logical_file_bytes = 0u64;
    for _ in 0..file_count {
        let rel_path = reader.read_string()?;
        validate_delta_rel_path(&rel_path)?;
        let len = reader.read_u64()?;
        logical_file_bytes = logical_file_bytes
            .checked_add(len)
            .ok_or_else(|| "delta object logical file size overflow".to_string())?;
        if logical_file_bytes > max_bytes {
            return Err(format!(
                "delta object logical file size {logical_file_bytes} exceeds {max_bytes} byte limit"
            ));
        }
        let payload_sha256 = reader.read_sha256()?;
        entries.push((rel_path, len, payload_sha256));
    }
    validate_distinct_delta_paths(entries.iter().map(|(path, _, _)| path.as_str()))?;

    let payload_count = reader.read_u64()?;
    let payload_count = usize::try_from(payload_count)
        .map_err(|_| "delta object payload count exceeds usize::MAX".to_string())?;
    let max_payload_count = reader.remaining_len() / DELTA_MIN_PAYLOAD_ENTRY_BYTES;
    if payload_count > file_count || payload_count > max_payload_count {
        return Err(format!(
            "delta object payload count {payload_count} exceeds canonical body bounds"
        ));
    }
    let mut payloads = BTreeMap::<([u8; 32], u64), Vec<u8>>::new();
    for _ in 0..payload_count {
        let payload_sha256 = reader.read_sha256()?;
        let payload_len = reader.read_u64()?;
        let len = usize::try_from(payload_len)
            .map_err(|_| "delta object payload length exceeds usize::MAX".to_string())?;
        let payload_bytes = reader.read_exact(len)?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(len)
            .map_err(|err| format!("reserve delta object payload: {err}"))?;
        payload.extend_from_slice(payload_bytes);
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

    let mut files = Vec::new();
    files
        .try_reserve(file_count)
        .map_err(|err| format!("reserve decoded delta files: {err}"))?;
    for (rel_path, len, payload_sha256) in entries {
        let payload = payloads.get(&(payload_sha256, len)).ok_or_else(|| {
            format!(
                "delta object missing payload {}:{} for {rel_path}",
                hex::encode(payload_sha256),
                len
            )
        })?;
        let mut file_bytes = Vec::new();
        file_bytes
            .try_reserve_exact(payload.len())
            .map_err(|err| format!("reserve decoded delta file {rel_path}: {err}"))?;
        file_bytes.extend_from_slice(payload);
        files.push(DeltaTreeFile {
            rel_path,
            bytes: file_bytes,
        });
    }
    reader.expect_eof()?;
    Ok(files)
}

fn commit_delta_tree_files(
    dest: &Path,
    files: &[DeltaTreeFile],
    object_sha256_hex: &str,
    max_bytes: u64,
) -> Result<(), String> {
    require_delta_directory(dest, "commit delta tree")?;
    validate_canonical_hex_hash(object_sha256_hex, "delta object sha256")?;
    let root_name = delta_tree_root_name(files)?;
    let final_target = dest.join(&root_name);
    if delta_path_metadata(&final_target, "inspect final delta target")?.is_some()
        && build_delta_source_snapshot(&final_target, max_bytes)
            .is_ok_and(|snapshot| snapshot.object_sha256_hex == object_sha256_hex)
    {
        return Ok(());
    }
    let state_dir = dest.join(DELTA_STATE_DIR);
    let staging_root = create_unique_delta_staging_root(&state_dir, object_sha256_hex)?;
    if let Err(error) = write_delta_files_under(&staging_root, files) {
        let _ = remove_delta_path_if_exists(&staging_root, "clean failed delta staging root");
        return Err(error);
    }

    let staged_target = staging_root.join(&root_name);
    let backup = if delta_path_metadata(&final_target, "inspect final delta target")?.is_some() {
        let backup_dir = state_dir.join("backups");
        create_delta_dir_all(&backup_dir, "create delta backup directory")?;
        let backup = (0..32u32)
            .map(|attempt| {
                backup_dir.join(format!(
                    "{}-{}-{attempt}",
                    sanitize_backup_name(&root_name),
                    unique_micros()
                ))
            })
            .find_map(|candidate| {
                match delta_path_metadata(&candidate, "allocate delta backup path") {
                    Ok(None) => Some(Ok(candidate)),
                    Ok(Some(_)) => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .transpose()?
            .ok_or_else(|| "could not allocate a unique delta backup path".to_string())?;
        rename_delta_path(
            &final_target,
            &backup,
            "move existing delta target to backup",
        )?;
        Some(backup)
    } else {
        None
    };

    match rename_delta_path(&staged_target, &final_target, "commit staged delta target") {
        Ok(()) => {
            let mut cleanup_errors = Vec::new();
            if let Some(backup) = backup.as_ref() {
                if let Err(error) =
                    remove_delta_path_if_exists(backup, "remove committed delta backup")
                {
                    cleanup_errors.push(error);
                }
            }
            if let Err(error) =
                remove_delta_path_if_exists(&staging_root, "remove committed delta staging root")
            {
                cleanup_errors.push(error);
            }
            if cleanup_errors.is_empty() {
                Ok(())
            } else {
                Err(cleanup_errors.join("; "))
            }
        }
        Err(commit_error) => {
            if let Some(backup) = backup.as_ref() {
                if let Err(rollback_error) =
                    rename_delta_path(backup, &final_target, "restore delta target backup")
                {
                    return Err(format!(
                        "{commit_error}; rollback also failed: {rollback_error}"
                    ));
                }
            }
            let _ = remove_delta_path_if_exists(&staging_root, "clean failed delta staging root");
            Err(commit_error)
        }
    }
}

fn write_delta_files_under(root: &Path, files: &[DeltaTreeFile]) -> Result<(), String> {
    validate_distinct_delta_paths(files.iter().map(|file| file.rel_path.as_str()))?;
    for file in files {
        let rel = safe_delta_path(&file.rel_path)?;
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            create_delta_dir_all(parent, "create delta output directory")?;
        }
        let mut output = create_delta_file(&path, "create delta output file")?;
        write_delta_file(&mut output, &path, &file.bytes, "write delta output file")?;
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

    fn remaining_len(&self) -> usize {
        self.bytes.len().saturating_sub(self.cursor)
    }

    fn expect_eof(&self) -> Result<(), String> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err("delta object has trailing bytes".to_string())
        }
    }
}

fn choose_data_host(args: &SendArgs, remote: &RemoteTarget, remote_shell: RemoteShell) -> String {
    if let Some(host) = &args.data_host {
        return host.clone();
    }
    if args.no_tailscale || args.prefer != PathPreference::Tailscale {
        return ssh_host_without_user(&remote.ssh_host).to_string();
    }
    probe_remote_tailscale_ipv4(args, &remote.ssh_host, remote_shell)
        .unwrap_or_else(|| ssh_host_without_user(&remote.ssh_host).to_string())
}

fn probe_remote_tailscale_ipv4(
    args: &SendArgs,
    ssh_host: &str,
    remote_shell: RemoteShell,
) -> Option<String> {
    let argv = ["tailscale".to_string(), "ip".to_string(), "-4".to_string()];
    let mut command = ssh_command(args, ssh_host);
    command.arg(remote_shell_command(remote_shell, &[], &argv).ok()?);
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
    remote_shell: RemoteShell,
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
        "--max-block-size".to_string(),
        args.max_block_size.remote_arg(),
        "--repair-overhead".to_string(),
        args.repair_overhead.to_string(),
        "--rq-round0-loss-pct".to_string(),
        args.rq_round0_loss_pct.to_string(),
        "--rq-tail-drain-ms".to_string(),
        args.rq_tail_drain_ms.to_string(),
    ];
    // Forward --symbol-size only when the local user set it explicitly: both
    // ends resolve the same per-transport default (1400 rq, 1144 quic), so an
    // omitted flag stays consistent across the pair — including through the
    // auto ladder, where each leg picks its own fitting default.
    if let Some(symbol_size) = args.symbol_size {
        argv.push("--symbol-size".to_string());
        argv.push(symbol_size.to_string());
    }
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

    let env_vars = match rq_auth {
        Some(RqAuthChoice::KeyHex(key_hex)) => vec![(RQ_AUTH_ENV, key_hex.as_str())],
        _ => Vec::new(),
    };
    let remote_command = remote_shell_command(remote_shell, &env_vars, &argv)?;
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
    ssh_base_command(&args.ssh_options, ssh_host)
}

fn ssh_base_command(ssh_options: &[String], ssh_host: &str) -> ProcessCommand {
    let mut command = ProcessCommand::new("ssh");
    command
        .arg("-T")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg("ConnectTimeout=15");
    for option in ssh_options {
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

fn wait_child_timeout(
    child: &mut Child,
    timeout: Duration,
    what: &str,
) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|err| err.to_string())? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{what} did not exit within {}s", timeout.as_secs()));
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

fn powershell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn powershell_encoded_command(
    env_vars: &[(&str, &str)],
    argv: &[String],
) -> Result<String, String> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| "remote command argv must not be empty".to_string())?;
    let mut script = "$ErrorActionPreference='Stop';$utf8=New-Object System.Text.UTF8Encoding($false);[Console]::OutputEncoding=$utf8;$OutputEncoding=$utf8;".to_string();
    for (name, value) in env_vars {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(format!("unsafe remote environment variable name: {name:?}"));
        }
        script.push_str("$env:");
        script.push_str(name);
        script.push('=');
        script.push_str(&powershell_single_quote(value));
        script.push(';');
    }
    script.push_str("& ");
    script.push_str(&powershell_single_quote(program));
    for arg in args {
        script.push(' ');
        script.push_str(&powershell_single_quote(arg));
    }
    script.push_str("; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }");

    let mut utf16le = Vec::with_capacity(script.len().saturating_mul(2));
    for unit in script.encode_utf16() {
        utf16le.extend_from_slice(&unit.to_le_bytes());
    }
    let encoded = STANDARD.encode(utf16le);
    let command =
        format!("powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}");
    // cmd.exe, still a common Windows OpenSSH default shell, has an 8191-byte
    // command-line ceiling. Fail explicitly instead of launching a truncated
    // command that might reinterpret the tail.
    if command.len() > 8_000 {
        return Err(format!(
            "encoded Windows remote command is {} bytes (maximum 8000)",
            command.len()
        ));
    }
    Ok(command)
}

fn remote_shell_command(
    shell: RemoteShell,
    env_vars: &[(&str, &str)],
    argv: &[String],
) -> Result<String, String> {
    match shell {
        RemoteShell::Posix => Ok(shell_command_with_env(env_vars, argv)),
        RemoteShell::Powershell => powershell_encoded_command(env_vars, argv),
        RemoteShell::Auto => {
            Err("remote shell must be resolved before command construction".to_string())
        }
    }
}

fn resolve_remote_shell(
    requested: RemoteShell,
    ssh_options: &[String],
    ssh_host: &str,
) -> Result<RemoteShell, String> {
    if requested != RemoteShell::Auto {
        return Ok(requested);
    }
    let probe_argv = [
        "cmd.exe".to_string(),
        "/d".to_string(),
        "/s".to_string(),
        "/c".to_string(),
        "echo ATP_WINDOWS_POWERSHELL".to_string(),
    ];
    let probe = powershell_encoded_command(&[], &probe_argv)?;
    let mut command = ssh_base_command(ssh_options, ssh_host);
    command
        .arg(probe)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let output = command
        .output()
        .map_err(|error| format!("probe remote shell on {ssh_host}: {error}"))?;
    if output.status.code() == Some(255) {
        return Err(format!(
            "probe remote shell on {ssh_host} failed: ssh exited with status {}",
            output.status
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.success()
        && stdout
            .lines()
            .any(|line| line.trim() == "ATP_WINDOWS_POWERSHELL")
    {
        Ok(RemoteShell::Powershell)
    } else {
        Ok(RemoteShell::Posix)
    }
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

async fn preflight_receive_destination(dest: &Path, operation: &str) -> Result<(), String> {
    let mut ancestors = dest
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        match path_is_link_or_reparse(&ancestor).await {
            Ok(true) => {
                return Err(format!(
                    "refusing to {operation} through symlink or reparse-point prefix {}",
                    ancestor.display()
                ));
            }
            Ok(false) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(format!(
                    "inspect receive destination prefix {} before {operation}: {err}",
                    ancestor.display()
                ));
            }
        }
    }
    Ok(())
}

async fn create_receive_destination(dest: &Path) -> Result<(), String> {
    preflight_receive_destination(dest, "create receive destination").await?;
    asupersync::fs::create_dir_all(dest)
        .await
        .map_err(|error| format!("create dest {}: {error}", dest.display()))?;
    preflight_receive_destination(dest, "use receive destination").await
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
    let max_bytes = args.max_bytes;
    let delta_enabled = cli_content_delta_enabled(args.no_delta);
    let direct_delta_sidecar_enabled = delta_enabled && args.allow_unauthenticated_delta_sidecar;

    match args.transport {
        Transport::Auto => Err(
            "atp recv/serve --transport auto is sender-only; choose tcp, rq, or quic".to_string(),
        ),
        Transport::Tcp => {
            let mut cfg = tcp_receive_config(args.max_bytes, !args.no_delta, one_shot);
            cfg.accept_timeout = recv_listen_timeout(&args)?;
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("receiver cx");
                create_receive_destination(&dest).await?;
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
                    handle_post_receive_delta(&dest, delta_enabled, max_bytes)?;
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
                                    handle_post_receive_delta(&delta_dest, delta_enabled, max_bytes)
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
            let symbol_size = resolved_symbol_size(args.symbol_size, false);
            let mut cfg = rq_config(
                args.max_bytes,
                symbol_size,
                1,
                args.max_block_size.effective(symbol_size)?,
                args.repair_overhead,
                args.rq_round0_loss_pct,
                args.rq_tail_drain_ms,
                args.rq_auth_key_hex.as_deref(),
                args.rq_allow_unauthenticated_lab,
            )?;
            cfg.accept_timeout = recv_listen_timeout(&args)?;
            let chosen_fanout = cfg.udp_fanout.max(1);
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("receiver cx");
                create_receive_destination(&dest).await?;
                let listener = TcpListener::bind(listen)
                    .await
                    .map_err(|e| format!("bind {listen}: {e}"))?;
                let bound = listener.local_addr().map_err(|e| e.to_string())?;
                let _delta_state_server =
                    spawn_delta_state_server(dest.clone(), bound, direct_delta_sidecar_enabled);
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
                    handle_post_receive_delta(&dest, delta_enabled, max_bytes)?;
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
                                    handle_post_receive_delta(&delta_dest, delta_enabled, max_bytes)
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
                    create_receive_destination(&dest).await?;
                    if one_shot {
                        let endpoint = bind_server_endpoint(&cx, listen)
                            .await
                            .map_err(|e| e.to_string())?;
                        let _delta_state_server = spawn_delta_state_server(
                            dest.clone(),
                            endpoint.local_addr(),
                            direct_delta_sidecar_enabled,
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
                        handle_post_receive_delta(&dest, delta_enabled, max_bytes)?;
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
                        let _delta_state_server = spawn_delta_state_server(
                            dest.clone(),
                            listen,
                            direct_delta_sidecar_enabled,
                        );
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
                                        handle_post_receive_delta(&dest, delta_enabled, max_bytes)
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
                Err("this atp binary was built without TLS (non-standard: the required atp-cli feature always bundles it) — rebuild with --features atp-cli".to_string())
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
        "udp_send_acceleration": report.udp_send_acceleration,
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

fn bond_donate_json(
    report: &transport_rq::BondedDonateReport,
    elapsed: Option<Duration>,
) -> serde_json::Value {
    serde_json::json!({
        "event": "atp_bond_donate", "transport": "rq",
        "transfer_id": report.transfer_id,
        "donor_index": report.donor_index,
        "donor_count": report.donor_count,
        "feedback_rounds": report.feedback_rounds,
        "committed": report.receipt.committed,
        "sha_ok": report.receipt.sha_ok,
        "merkle_ok": report.receipt.merkle_ok,
        "receiver_endpoints": report
            .spray
            .receiver_endpoints
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "entries": report.spray.entries,
        "blocks": report.spray.blocks,
        "source_symbols_sent": report.spray.source_symbols_sent,
        "repair_symbols_sent": report.spray.repair_symbols_sent,
        "round0_symbols_sent": report.spray.symbols_sent,
        "symbols_sent": report.symbols_sent,
        "round0_payload_bytes": report.spray.udp_send_acceleration.payload_bytes,
        "pacing": {
            "initial_rate_bytes_per_sec": report.spray.pacing.initial_rate_bytes_per_sec,
            "final_rate_bytes_per_sec": report.spray.pacing.final_rate_bytes_per_sec,
            "burst_symbols": report.spray.pacing.burst_symbols,
            "burst_bytes": report.spray.pacing.burst_bytes,
            "datagram_bytes": report.spray.pacing.datagram_bytes,
            "clean_round0_ramp_enabled": report.spray.pacing.clean_round0_ramp_enabled,
        },
        "udp_send_acceleration": report.spray.udp_send_acceleration,
        "metrics": atp_metrics_json(
            report.spray.udp_send_acceleration.payload_bytes,
            Some(report.symbols_sent),
            Some(report.receipt.symbols_accepted),
            report.feedback_rounds,
            None,
            None,
            report.spray.receiver_endpoints.len(),
            elapsed,
        ),
    })
}

fn bond_recv_json(
    report: &transport_rq::BondedReceiveReport,
    chosen_fanout: usize,
    elapsed: Option<Duration>,
) -> serde_json::Value {
    serde_json::json!({
        "event": "atp_bond_receive", "transport": "rq",
        "transfer_id": report.transfer_id,
        "committed": report.committed,
        "bytes_received": report.bytes_received,
        "files": report.files,
        "symbols_accepted": report.symbols_accepted,
        "feedback_rounds": report.feedback_rounds,
        "enrolled_donors": report.enrolled_donors,
        "reallocated_repair_windows": report.reallocated_repair_windows,
        "donor_ingress": report
            .donor_ingress
            .iter()
            .map(|(donor_index, stats)| serde_json::json!({
                "donor_index": donor_index,
                "symbols_received": stats.symbols_received,
                "symbols_accepted": stats.symbols_accepted,
                "duplicate_symbols": stats.duplicate_symbols,
                "source_symbols_accepted": stats.source_symbols_accepted,
                "repair_symbols_accepted": stats.repair_symbols_accepted,
                "symbols_rejected_by_retention": stats.symbols_rejected_by_retention,
            }))
            .collect::<Vec<_>>(),
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

    #[test]
    fn symbol_size_defaults_per_transport_and_respects_explicit_values() {
        use asupersync::net::atp::transport_quic::QUIC_DEFAULT_SYMBOL_SIZE;
        // No flag: each transport gets a default that just works.
        assert_eq!(resolved_symbol_size(None, false), DEFAULT_SYMBOL_SIZE);
        assert_eq!(resolved_symbol_size(None, true), QUIC_DEFAULT_SYMBOL_SIZE);
        // Explicit values always win — including ones that will fail closed
        // downstream (an explicit 1400 on quic must NOT be silently shrunk).
        assert_eq!(resolved_symbol_size(Some(1400), true), 1400);
        assert_eq!(resolved_symbol_size(Some(512), false), 512);
    }

    #[test]
    fn cli_content_delta_falls_back_when_metadata_must_be_preserved() {
        assert!(!cli_delta_policy_is_content_only(&MetadataPolicy::default()));
        assert!(cli_delta_policy_is_content_only(&MetadataPolicy::portable()));
        assert!(!cli_content_delta_enabled(false));
        assert!(!cli_content_delta_enabled(true));
    }

    #[test]
    fn cli_defaults_preserve_timestamps_and_hardlinks() {
        let policy = selected_cli_metadata_policy();
        assert!(policy.preserve_timestamps);
        let tcp = tcp_config(DEFAULT_MAX_TRANSFER_BYTES, true);
        assert_eq!(tcp.metadata_policy, policy);
        assert!(tcp.preserve_hardlinks);
        let rq = rq_config(
            DEFAULT_MAX_TRANSFER_BYTES,
            DEFAULT_SYMBOL_SIZE,
            1,
            AUTO_MAX_BLOCK_SIZE,
            DEFAULT_REPAIR_OVERHEAD,
            0.0,
            DEFAULT_ROUND_TAIL_DRAIN_MS,
            Some(VALID_KEY_HEX),
            false,
        )
        .expect("RQ CLI config");
        assert_eq!(rq.metadata_policy, policy);
        assert!(rq.preserve_hardlinks);
    }

    #[test]
    fn rq_send_config_maps_nondefault_send_args_exactly() {
        let args = SendArgs::try_parse_from([
            "atp-send",
            "payload.bin",
            "127.0.0.1:8472",
            "--transport",
            "rq",
            "--max-bytes",
            "999999",
            "--symbol-size",
            "1024",
            "--streams",
            "3",
            "--max-block-size",
            "65536",
            "--repair-overhead",
            "1.25",
            "--rq-round0-loss-pct",
            "2.5",
            "--rq-tail-drain-ms",
            "17",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
        ])
        .expect("parse RQ send args");

        let from_args = rq_send_config(&args).expect("effective RQ send config");
        let direct = rq_config(
            999_999,
            1024,
            3,
            65_536,
            1.25,
            2.5,
            17,
            Some(VALID_KEY_HEX),
            false,
        )
        .expect("direct RQ config");

        assert_eq!(from_args.symbol_size, direct.symbol_size);
        assert_eq!(from_args.max_block_size, direct.max_block_size);
        assert_eq!(from_args.udp_fanout, direct.udp_fanout);
        assert_eq!(from_args.max_transfer_bytes, direct.max_transfer_bytes);
        assert_eq!(from_args.repair_overhead, direct.repair_overhead);
        assert_eq!(from_args.round0_loss_target, direct.round0_loss_target);
        assert_eq!(from_args.round_tail_drain, direct.round_tail_drain);
        assert_eq!(from_args.metadata_policy, direct.metadata_policy);
        assert_eq!(from_args.preserve_hardlinks, direct.preserve_hardlinks);
        assert_eq!(from_args.symbol_auth_mode(), direct.symbol_auth_mode());
    }

    #[test]
    fn rq_dry_run_rejects_the_same_hardlink_topology_as_send() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let source = temp.path().join("payload");
        fs::create_dir(&source).expect("source root");
        fs::write(source.join("primary.bin"), b"same inode").expect("primary file");
        fs::hard_link(source.join("primary.bin"), source.join("duplicate.bin"))
            .expect("hardlink duplicate");
        let source_arg = source.to_str().expect("UTF-8 temp path");
        let args = SendArgs::try_parse_from([
            "atp-send",
            source_arg,
            "127.0.0.1:8472",
            "--transport",
            "rq",
            "--rq-auth-key-hex",
            VALID_KEY_HEX,
        ])
        .expect("parse RQ dry-run args");

        let error =
            run_send_dry_run(&args).expect_err("dry-run must apply real-send hardlink validation");
        assert!(error.contains("cannot preserve hardlink identity"));
    }

    #[test]
    fn cached_delta_match_never_commits_without_live_receiver_receipt() {
        assert!(cached_delta_match_requires_live_transfer(
            DeltaResyncMode::AlreadyInSync
        ));
        assert!(!cached_delta_match_requires_live_transfer(
            DeltaResyncMode::DeltaChunks
        ));
    }

    #[test]
    fn user_sources_reject_reserved_delta_names_recursively() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let source = temp.path().join("payload");
        fs::create_dir(&source).expect("source directory");
        fs::write(source.join("ordinary.bin"), b"ok").expect("ordinary source file");
        validate_user_transfer_namespace(&source).expect("ordinary source namespace");

        let reserved = source.join(".AsUpErSyNc-AtP-DeLtA-PaCkAgE-user");
        fs::create_dir(&reserved).expect("reserved fixture directory");
        let error = validate_user_transfer_namespace(&source)
            .expect_err("reserved package namespace must reject before transfer");
        assert!(error.contains("reserved ATP delta namespace"));

        let state_root = temp.path().join(DELTA_STATE_DIR);
        fs::create_dir(&state_root).expect("reserved state fixture");
        assert!(validate_user_transfer_namespace(&state_root).is_err());
    }

    #[test]
    fn transfer_size_limit_accepts_exact_and_rejects_limit_plus_one() {
        enforce_transfer_size("test source", 8, 8).expect("exact size limit");
        let error = enforce_transfer_size("test source", 9, 8)
            .expect_err("dry-run size limit plus one must reject");
        assert!(error.contains("exceeds --max-bytes 8"));
    }

    #[test]
    fn delta_snapshot_enforces_logical_and_encoded_max_bytes() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let source = temp.path().join("payload.bin");
        fs::write(&source, b"123456789").expect("source fixture");
        let error = build_delta_source_snapshot(&source, 8)
            .expect_err("sender snapshot must enforce max bytes while reading");
        assert!(error.contains("exceeds 8 byte limit"));

        fs::write(&source, b"").expect("empty source fixture");
        let error = build_delta_source_snapshot(&source, 0)
            .expect_err("encoded delta object overhead must enforce max bytes");
        assert!(error.contains("encoded delta object size"));

        let repeated = vec![0x5a; 8 * 1024];
        let files = vec![
            DeltaTreeFile {
                rel_path: "tree/a.bin".to_string(),
                bytes: repeated.clone(),
            },
            DeltaTreeFile {
                rel_path: "tree/b.bin".to_string(),
                bytes: repeated,
            },
        ];
        let encoded = encode_delta_tree_object(&files).expect("encode repeated payload tree");
        let encoded_limit = u64::try_from(encoded.len()).expect("encoded fixture length");
        assert!(encoded_limit < 16 * 1024);
        let error = decode_delta_tree_object(&encoded, encoded_limit)
            .expect_err("logical decoded size above max bytes must reject");
        assert!(error.contains("logical file size"));

        let error = decode_delta_tree_object(&encoded, encoded_limit - 1)
            .expect_err("encoded object above max bytes must reject before decode");
        assert!(error.contains("encoded delta object size"));

        let payload = b"123456789".to_vec();
        let snapshot = one_chunk_delta_snapshot("max-bytes-test", payload.clone());
        let mut store = DeltaChunkStore::new();
        store
            .insert(&payload)
            .expect("insert reconstruction fixture");
        let error = reconstruct_delta_object_bytes(&snapshot.manifest, &store, 8)
            .expect_err("reconstruction must enforce receiver max bytes");
        assert!(error.contains("exceeds 8 byte limit"));
    }

    #[test]
    fn delta_commit_retry_removes_staging_and_backup_artifacts() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let dest = temp.path().join("dest");
        let old_root = dest.join("tree");
        fs::create_dir_all(&old_root).expect("old destination tree");
        fs::write(old_root.join("payload.bin"), b"old").expect("old destination file");

        let files = vec![DeltaTreeFile {
            rel_path: "tree/payload.bin".to_string(),
            bytes: b"new".to_vec(),
        }];
        let encoded = encode_delta_tree_object(&files).expect("encode replacement tree");
        let object_sha256_hex = hex::encode(Sha256::digest(&encoded));
        commit_delta_tree_files(
            &dest,
            &files,
            &object_sha256_hex,
            DEFAULT_MAX_TRANSFER_BYTES,
        )
        .expect("commit replacement tree");
        assert_eq!(fs::read(old_root.join("payload.bin")).unwrap(), b"new");

        let state_dir = dest.join(DELTA_STATE_DIR);
        let names = fs::read_dir(&state_dir)
            .expect("delta state directory")
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(!names.iter().any(|name| name.starts_with("staging-")));
        let backup_dir = state_dir.join("backups");
        assert_eq!(
            fs::read_dir(&backup_dir).expect("backup directory").count(),
            0
        );

        commit_delta_tree_files(
            &dest,
            &files,
            &object_sha256_hex,
            DEFAULT_MAX_TRANSFER_BYTES,
        )
        .expect("idempotent retry of committed tree");
    }

    #[test]
    fn sender_delta_package_guard_removes_successful_package() {
        let package_root =
            create_unique_delta_package_root(&"a".repeat(64)).expect("temporary delta package");
        fs::write(package_root.join("payload"), b"test").expect("package fixture");
        let mut guard = DeltaPackageRootGuard::new(package_root.clone()).expect("package guard");
        guard.cleanup().expect("remove sender package");
        assert!(!package_root.exists());
    }

    #[test]
    fn delta_paths_reject_windows_aliases_before_materialization() {
        validate_delta_rel_path("nested/payload.bin").expect("portable delta path");
        for path in [
            "NUL.txt",
            "nested/COM1.log",
            "trailing.",
            "trailing ",
            "alternate:stream",
            ".asupersync-atp-delta-v1/state.json",
            ".ASUPERSYNC-ATP-DELTA-V1/state.json",
            ".AsUpErSyNc-AtP-DeLtA-PaCkAgE-1/payload",
        ] {
            assert!(
                validate_delta_rel_path(path).is_err(),
                "Windows-unsafe delta path {path:?} must fail closed"
            );
        }

        assert!(validate_distinct_delta_paths(["Docs/Readme", "docs/README"]).is_err());
        assert!(
            validate_distinct_delta_paths(["root/Foo/a", "root/foo/b"]).is_err(),
            "case-colliding directory prefixes must reject before Windows materialization"
        );
    }

    #[test]
    fn delta_package_payload_names_are_exact_and_canonical() {
        let target = "a".repeat(64);
        let base = "b".repeat(64);
        let chunk = canonical_delta_chunk_file_name(&target).expect("canonical chunk name");
        let ops = canonical_delta_ops_file_name(&target, &base).expect("canonical ops name");
        require_canonical_delta_file_name(&chunk, &chunk, "chunk").expect("exact chunk name");
        require_canonical_delta_file_name(&ops, &ops, "ops").expect("exact ops name");

        for malicious in [
            "../payload.chunk",
            "/payload.chunk",
            "C:\\payload.chunk",
            "payload:stream",
            "nested/payload.chunk",
            "nested\\payload.chunk",
        ] {
            assert!(
                require_canonical_delta_file_name(malicious, &chunk, "chunk").is_err(),
                "malicious package filename {malicious:?} must reject"
            );
        }
        assert!(canonical_delta_chunk_file_name(&target.to_ascii_uppercase()).is_err());
        assert!(
            require_canonical_delta_file_name(&format!("{}.bin", target), &chunk, "chunk").is_err()
        );
    }

    #[test]
    fn delta_object_counts_are_bounded_by_remaining_body_before_reserve() {
        let mut huge_file_count = DELTA_TREE_OBJECT_MAGIC.to_vec();
        put_u64(&mut huge_file_count, 1_000_001);
        let error = decode_delta_tree_object(&huge_file_count, DEFAULT_MAX_TRANSFER_BYTES)
            .expect_err("huge count with tiny body must reject before allocation");
        assert!(error.contains("file count") || error.contains("payload count"));

        let mut huge_payload_count = DELTA_TREE_OBJECT_MAGIC.to_vec();
        put_u64(&mut huge_payload_count, 1);
        put_len_prefixed(&mut huge_payload_count, b"root/file").expect("test path");
        put_u64(&mut huge_payload_count, 0);
        huge_payload_count.extend_from_slice(&sha256_array(&[]));
        put_u64(&mut huge_payload_count, 1_000_000);
        let error = decode_delta_tree_object(&huge_payload_count, DEFAULT_MAX_TRANSFER_BYTES)
            .expect_err("huge payload count with tiny body must reject before allocation");
        assert!(error.contains("payload count"));

        let mut huge_op_count = DELTA_SUBDELTA_OPS_MAGIC.to_vec();
        put_u64(&mut huge_op_count, 1_000_000);
        let error = validate_subdelta_op_count_before_decode(&huge_op_count)
            .expect_err("huge sub-delta op count must reject before decoder allocation");
        assert!(error.contains("op count"));
    }

    #[test]
    fn delta_exact_file_reader_rejects_declared_limit_plus_one() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let path = temp.path().join("payload.chunk");
        fs::write(&path, b"123456789").expect("write oversized fixture");
        let error = read_delta_file_exact_before(&path, 8, 8, None, "read test chunk")
            .expect_err("declared size plus one must reject");
        assert!(error.contains("exceeds 8 byte limit"));

        let error = read_delta_file_exact_before(&path, 9, 8, None, "read test chunk")
            .expect_err("declared size above hard cap must reject before read");
        assert!(error.contains("declared size 9 exceeds 8 byte limit"));
    }

    #[test]
    fn empty_directory_delta_snapshot_selects_capability_fallback() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let error = collect_delta_tree_files(temp.path(), DEFAULT_MAX_TRANSFER_BYTES)
            .expect_err("empty directory must not produce an unappliable delta object");
        assert!(matches!(
            error,
            DeltaSnapshotFailure::UnsupportedCapability(_)
        ));
    }

    #[test]
    fn full_transfer_ignores_only_capability_limited_delta_refresh() {
        assert!(
            finish_delta_refresh(
                0,
                Err(DeltaSnapshotFailure::unsupported("unsupported metadata"))
            )
            .is_ok()
        );
        assert!(
            finish_delta_refresh(0, Err(DeltaSnapshotFailure::fatal("tampered state"))).is_err()
        );
        assert!(
            finish_delta_refresh(
                1,
                Err(DeltaSnapshotFailure::unsupported("unsupported metadata"))
            )
            .is_err()
        );
    }

    #[test]
    fn persistent_tcp_receive_serializes_destination_commits() {
        assert_eq!(
            tcp_receive_config(1024, true, false).max_active_connections,
            1
        );
        assert_eq!(
            tcp_receive_config(1024, true, true).max_active_connections,
            TransferConfig::default().max_active_connections
        );
    }

    #[test]
    fn ssh_bootstrap_rejects_windows_shell_paths() {
        assert!(RemoteTarget::parse(r"host:C:\inbox").is_some());
        for path in [
            r"C:\inbox",
            "D:/inbox",
            r"\\server\share\inbox",
            r"bin\atp.exe",
        ] {
            let error = validate_posix_ssh_path("test", path)
                .expect_err("Windows path must reject before SSH bootstrap");
            assert!(error.contains("directly on Windows"));
        }
        for path in ["/srv/inbox", "~/bin/atp", "./bin/atp"] {
            validate_posix_ssh_path("test", path).expect("POSIX path");
        }
    }

    #[cfg(unix)]
    #[test]
    fn delta_path_guard_rejects_symlink_ancestor_before_create() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temporary directory");
        let target = temp.path().join("target");
        fs::create_dir(&target).expect("target directory");
        let link = temp.path().join("link");
        symlink(&target, &link).expect("create symlink");
        let destination = link.join("must-not-exist");

        assert!(ensure_delta_path_chain(&destination, "test create").is_err());
        assert!(!target.join("must-not-exist").exists());
    }

    #[cfg(windows)]
    #[test]
    fn delta_path_guard_rejects_junction_ancestor_before_create() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let target = temp.path().join("target");
        fs::create_dir(&target).expect("target directory");
        let junction = temp.path().join("junction");
        let status = ProcessCommand::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&junction)
            .arg(&target)
            .status()
            .expect("run mklink /J");
        assert!(
            status.success(),
            "mklink /J must succeed so the Windows junction guard is actually tested: {status}"
        );
        let destination = junction.join("must-not-exist");

        assert!(ensure_delta_path_chain(&destination, "test create").is_err());
        assert!(!target.join("must-not-exist").exists());
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_fd_limit_setup_is_a_noop() {
        raise_fd_limit();
    }

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
        assert_eq!(config.udp_fanout, 4);
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

        let recv_timeout =
            RecvArgs::try_parse_from(["recv", "/tmp/dest", "--once", "--accept-timeout-secs", "2"])
                .expect("recv parser should accept bounded one-shot accept timeout");
        assert_eq!(recv_timeout.accept_timeout_secs, 2);
        assert_eq!(
            recv_listen_timeout(&recv_timeout),
            Ok(Duration::from_secs(2))
        );

        let recv_timeout_ms = RecvArgs::try_parse_from([
            "recv",
            "/tmp/dest",
            "--once",
            "--listen-timeout-ms",
            "1500",
        ])
        .expect("recv parser should accept millisecond listen timeout override");
        assert_eq!(
            recv_listen_timeout(&recv_timeout_ms),
            Ok(Duration::from_millis(1500))
        );
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
    fn max_block_size_arg_auto_uses_quic_bounded_decode_ceiling() {
        assert_eq!(
            MaxBlockSizeArg::Auto.effective_for_quic(1024),
            Ok(QUIC_AUTO_MAX_BLOCK_SIZE)
        );
        assert_eq!(
            MaxBlockSizeArg::Bytes(512 * 1024).effective_for_quic(1024),
            Ok(512 * 1024)
        );
        assert_eq!(QUIC_AUTO_MAX_BLOCK_SIZE, AUTO_MAX_BLOCK_SIZE);
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
    fn rq_tail_drain_calibrates_only_lossy_matrix_cells() {
        assert_eq!(
            calibrated_rq_tail_drain_ms(0.0, DEFAULT_ROUND_TAIL_DRAIN_MS),
            DEFAULT_ROUND_TAIL_DRAIN_MS,
            "clean cells should keep the short tail drain"
        );
        assert_eq!(
            calibrated_rq_tail_drain_ms(0.001, DEFAULT_ROUND_TAIL_DRAIN_MS),
            DEFAULT_ROUND_TAIL_DRAIN_MS,
            "good/near-clean cells should not pay the lossy quiet window"
        );
        assert_eq!(
            calibrated_rq_tail_drain_ms(0.02, DEFAULT_ROUND_TAIL_DRAIN_MS),
            RQ_BAD_LINK_TAIL_DRAIN_MS,
            "bad cells need enough quiet drain for delayed UDP tails"
        );
        assert_eq!(
            calibrated_rq_tail_drain_ms(0.10, DEFAULT_ROUND_TAIL_DRAIN_MS),
            RQ_BROKEN_LINK_TAIL_DRAIN_MS,
            "broken cells need a wider quiet drain than the 2 ms clean default"
        );
        assert_eq!(
            calibrated_rq_tail_drain_ms(0.10, 0),
            0,
            "an explicit zero still disables tail drain for diagnostics"
        );
        assert_eq!(
            calibrated_rq_tail_drain_ms(0.10, 250),
            250,
            "operator-provided wider drains are preserved"
        );
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

    #[cfg(feature = "tls")]
    #[test]
    fn direct_quic_uses_transport_auth_even_when_rq_key_is_configured() {
        let cfg = quic_with_transport_auth(
            asupersync::net::atp::transport_quic::QuicConfig::default(),
            Some(VALID_KEY_HEX),
            false,
        );

        assert_eq!(
            cfg.symbol_auth_mode(),
            asupersync::net::atp::transport_quic::QuicSymbolAuthMode::TransportAuthenticated
        );
        assert!(cfg.validate().is_ok());
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
    fn windows_remote_command_is_utf16_encoded_and_injection_safe() {
        let argv = vec![
            r"C:\Program Files\ATP\atp.exe".to_string(),
            "recv".to_string(),
            r"C:\incoming folder\O'Brien".to_string(),
            "unicode-λ".to_string(),
        ];
        let command = powershell_encoded_command(&[(RQ_AUTH_ENV, VALID_KEY_HEX)], &argv)
            .expect("encode PowerShell command");
        let encoded = command
            .split_whitespace()
            .last()
            .expect("encoded-command payload");
        let bytes = STANDARD.decode(encoded).expect("base64 payload");
        assert_eq!(bytes.len() % 2, 0);
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let script = String::from_utf16(&units).expect("UTF-16LE PowerShell script");

        assert!(script.contains("[Console]::OutputEncoding=$utf8"));
        assert!(script.contains("$env:ATP_RQ_AUTH_KEY_HEX='000102"));
        assert!(script.contains("& 'C:\\Program Files\\ATP\\atp.exe' 'recv'"));
        assert!(script.contains(r"'C:\incoming folder\O''Brien'"));
        assert!(script.contains("'unicode-λ'"));
        assert!(script.ends_with("if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"));
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
        let pinned_leaf = cert.as_ref().to_vec();
        let config =
            quic_cli_client_config(vec![cert], vec![pinned_leaf], vec![ATP_QUIC_ALPN.to_vec()])
                .expect("leaf PEM supplied via --ca should build pinned verifier");

        assert_eq!(config.alpn_protocols, vec![ATP_QUIC_ALPN.to_vec()]);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn quic_cli_client_config_accepts_unpinned_trust_roots() {
        use asupersync::net::quic_native::handshake_driver::ATP_QUIC_ALPN;

        let cert = parse_quic_pinned_leaf_cert();
        let config = quic_cli_client_config(vec![cert], Vec::new(), vec![ATP_QUIC_ALPN.to_vec()])
            .expect("system-style roots should use the standard WebPKI verifier");

        assert_eq!(config.alpn_protocols, vec![ATP_QUIC_ALPN.to_vec()]);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn quic_cli_native_roots_tolerate_malformed_entries_but_require_one_valid_anchor() {
        use asupersync::net::quic_native::handshake_driver::ATP_QUIC_ALPN;
        use asupersync::net::quic_native::tls::QuicTlsError;

        let invalid = rustls::pki_types::CertificateDer::from(vec![0, 1, 2, 3]);
        let valid = parse_quic_pinned_leaf_cert();
        quic_cli_client_config(
            vec![invalid.clone(), valid],
            Vec::new(),
            vec![ATP_QUIC_ALPN.to_vec()],
        )
        .expect("one malformed native entry must not discard valid system roots");

        let error = quic_cli_client_config(vec![invalid], Vec::new(), vec![ATP_QUIC_ALPN.to_vec()])
            .expect_err("an entirely invalid native store must fail closed");
        assert!(matches!(
            error,
            QuicTlsError::CryptoProviderFailure {
                code: "client_no_valid_native_roots",
                ..
            }
        ));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn native_root_loading_rejects_environment_store_replacement() {
        let injected = std::ffi::OsStr::new("/tmp/injected-ca.pem");
        assert!(reject_environment_selected_native_roots(None, None).is_ok());
        for (file, dir) in [(Some(injected), None), (None, Some(injected))] {
            let error = reject_environment_selected_native_roots(file, dir)
                .expect_err("environment-selected roots must require explicit --ca");
            assert!(error.contains("--ca"));
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn auto_fallback_only_admits_pre_transfer_quic_failures() {
        use asupersync::net::atp::transport_quic::QuicTransportError;

        assert!(
            classify_quic_send_failure(QuicTransportError::Quic(
                "quic handshake: certificate unknown".to_string()
            ))
            .fallback_eligible
        );
        assert!(
            classify_quic_send_failure(QuicTransportError::Timeout {
                operation: "receive sender handshake ack",
                timeout: Duration::from_secs(1),
            })
            .fallback_eligible
        );
        assert!(
            !classify_quic_send_failure(QuicTransportError::Integrity(
                "tampered manifest".to_string()
            ))
            .fallback_eligible
        );
        assert!(
            !classify_quic_send_failure(QuicTransportError::Quic(
                "packet protection: invalid tag".to_string()
            ))
            .fallback_eligible
        );
    }

    #[test]
    fn auto_fallback_only_admits_pre_transfer_rq_rejection() {
        assert!(
            classify_rq_send_failure(RqError::HandshakeRejected("unsupported".to_string()))
                .fallback_eligible
        );
        assert!(
            !classify_rq_send_failure(RqError::Integrity("tampered manifest".to_string()))
                .fallback_eligible
        );
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
    fn auto_transport_order_requires_opt_in_for_unencrypted_fallbacks() {
        assert_eq!(
            Transport::auto_fallback_order(false, false, true),
            &[Transport::Quic]
        );
        assert_eq!(
            Transport::auto_fallback_order(false, true, true),
            &[Transport::Quic, Transport::Rq, Transport::Tcp]
        );
        assert_eq!(
            Transport::auto_fallback_order(false, true, false),
            &[Transport::Quic, Transport::Tcp]
        );
        assert_eq!(Transport::Auto.cli_arg(), "auto");
    }

    #[test]
    fn auto_transport_delta_requires_plaintext_opt_in() {
        assert!(Transport::auto_fallback_order(true, false, true).is_empty());
        assert_eq!(
            Transport::auto_fallback_order(true, true, true),
            &[Transport::Tcp]
        );
    }

    #[test]
    fn auto_security_policy_allows_default_metadata_preserving_path() {
        let cli = Cli::parse_from([
            "atp",
            "send",
            "./src",
            "receiver.example:8472",
            "--transport",
            "auto",
        ]);
        let Command::Send(args) = cli.command else {
            panic!("expected send command");
        };

        validate_auto_security_policy(&args)
            .expect("default metadata-preserving policy selects authenticated QUIC");
        assert_eq!(
            Transport::auto_fallback_order(
                cli_content_delta_enabled(args.no_delta),
                args.allow_plaintext_fallback,
                false,
            ),
            &[Transport::Quic]
        );
    }

    #[test]
    fn auto_security_policy_allows_explicit_plaintext_fallback() {
        let cli = Cli::parse_from([
            "atp",
            "send",
            "./src",
            "receiver.example:8472",
            "--transport",
            "auto",
            "--allow-plaintext-fallback",
        ]);
        let Command::Send(args) = cli.command else {
            panic!("expected send command");
        };

        validate_auto_security_policy(&args).expect("operator explicitly allowed downgrade");
    }

    #[test]
    fn plaintext_fallback_flag_rejects_non_auto_transport() {
        let cli = Cli::parse_from([
            "atp",
            "send",
            "./src",
            "receiver.example:8472",
            "--transport",
            "tcp",
            "--allow-plaintext-fallback",
        ]);
        let Command::Send(args) = cli.command else {
            panic!("expected send command");
        };

        assert!(validate_auto_security_policy(&args).is_err());
    }

    #[test]
    fn direct_delta_sidecar_is_disabled_without_explicit_lab_opt_in() {
        let cli = Cli::parse_from([
            "atp",
            "send",
            "./source-does-not-need-to-exist",
            "127.0.0.1:9",
            "--transport",
            "quic",
        ]);
        let Command::Send(args) = cli.command else {
            panic!("expected send command");
        };

        assert!(
            prepare_direct_delta_send(&args, "127.0.0.1:9".parse().unwrap())
                .expect("disabled sidecar must not perform network I/O")
                .is_none()
        );
    }

    #[test]
    fn delta_tree_chunker_uses_smaller_content_defined_chunks() {
        // Deterministic high-entropy fixture data. Affine byte patterns like
        // `(idx * 31 + idx / 7) % 251` are short-periodic, so the whole
        // stream contains only ~1.7k distinct hash windows — far too few for
        // any content-defined boundary rule targeting 32 KiB averages.
        let data = delta_tree_fixture_bytes(512 * 1024, 0x5eed);

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
        let mut original = delta_tree_fixture_bytes(768 * 1024, 0xfeed);
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
        let original = delta_tree_fixture_bytes(2 * 1024 * 1024, 0xabcd);
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
        let decoded = decode_delta_tree_object(&encoded, DEFAULT_MAX_TRANSFER_BYTES)
            .expect("decode moved tree object");
        assert_eq!(decoded.len(), after.len());
        for (observed, expected) in decoded.iter().zip(&after) {
            assert_eq!(observed.rel_path, expected.rel_path);
            assert_eq!(observed.bytes, expected.bytes);
        }

        let receiver = build_delta_snapshot_from_files(before, DEFAULT_MAX_TRANSFER_BYTES)
            .expect("receiver snapshot");
        let sender = build_delta_snapshot_from_files(after, DEFAULT_MAX_TRANSFER_BYTES)
            .expect("sender snapshot");
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
                chunks: vec![
                    DeltaSubchunkSignatureRequestChunk {
                        content_id_hex: chunk.content_id.to_hex(),
                        size_bytes: chunk.size_bytes,
                    },
                    DeltaSubchunkSignatureRequestChunk {
                        content_id_hex: chunk.content_id.to_hex(),
                        size_bytes: chunk.size_bytes,
                    },
                ],
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
    fn delta_sidecar_retry_filter_only_retries_transient_connect_failures() {
        use std::io::{Error, ErrorKind};

        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::TimedOut,
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::AddrNotAvailable,
        ] {
            assert!(retryable_delta_state_connect_error(&Error::from(kind)));
        }
        assert!(!retryable_delta_state_connect_error(&Error::from(
            ErrorKind::PermissionDenied,
        )));
        assert!(!retryable_delta_state_connect_error(&Error::from(
            ErrorKind::InvalidInput,
        )));
    }

    #[test]
    fn delta_sidecar_reader_accepts_exact_limit_and_rejects_limit_plus_one() {
        let mut exact = std::io::Cursor::new(b"12345678".to_vec());
        assert_eq!(
            read_utf8_body_limited(&mut exact, 8).expect("exact limit should fit"),
            "12345678"
        );

        let mut oversized = std::io::Cursor::new(b"123456789".to_vec());
        let error =
            read_utf8_body_limited(&mut oversized, 8).expect_err("limit plus one must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds 8 byte limit"));
    }

    #[test]
    fn delta_sidecar_json_encoder_stops_at_limit() {
        assert_eq!(
            encode_json_body_limited(&"1234", 6).expect("encoded JSON is exactly six bytes"),
            br#""1234""#
        );
        let error = encode_json_body_limited(&"1234", 5)
            .expect_err("bounded writer must reject an oversized response");
        assert!(error.contains("exceeds 5 byte limit"));
    }

    #[test]
    fn delta_sidecar_signature_work_budget_accepts_limit_and_rejects_limit_plus_one() {
        let mut used = 0;
        charge_delta_signature_blocks(&mut used, 8, 8).expect("exact work limit should fit");
        assert_eq!(used, 8);
        let error = charge_delta_signature_blocks(&mut used, 1, 8)
            .expect_err("work limit plus one must fail before signature allocation");
        assert!(error.contains("8 block work limit"));
        assert_eq!(used, 8);
    }

    #[test]
    fn delta_sidecar_request_enforces_absolute_deadline_against_trickle() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("loopback addr");
        let writer = thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(addr).expect("connect loopback");
            for _ in 0..20 {
                if stream.write_all(b" ").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        let (mut stream, _) = listener.accept().expect("accept loopback");
        let started = Instant::now();
        let error =
            read_delta_state_sidecar_request(&mut stream, started + Duration::from_millis(60))
                .expect_err("continuous trickle must not extend the absolute deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(500));
        writer.join().expect("join trickle writer");
    }

    #[test]
    fn delta_sidecar_client_read_enforces_absolute_deadline_against_trickle() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("loopback addr");
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept loopback");
            for _ in 0..20 {
                if stream.write_all(b" ").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        let mut stream = std::net::TcpStream::connect(addr).expect("connect loopback");
        let started = Instant::now();
        let error =
            read_utf8_body_before_deadline(&mut stream, 1024, started + Duration::from_millis(60))
                .expect_err("peer trickle must not reset the client deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(500));
        writer.join().expect("join trickle writer");
    }

    #[test]
    fn delta_sidecar_file_reader_rejects_limit_plus_one() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let path = temp.path().join("oversized-state.json");
        fs::write(&path, b"123456789").expect("write oversized fixture");
        let mut file = fs::File::open(&path).expect("open oversized fixture");

        let error = read_file_limited_before_deadline(&mut file, 8, None, "read test delta state")
            .expect_err("limit+1 file must reject before unbounded allocation");

        assert!(error.contains("exceeds 8 byte limit"));
    }

    #[test]
    fn delta_sidecar_json_parse_honors_expired_compute_deadline() {
        let deadline = Instant::now();
        let error = decode_json_body_before_deadline::<DeltaSubchunkSignatureRequest>(
            br#"{"schema":"ignored","chunks":[]}"#,
            deadline,
            "parse test request",
        )
        .expect_err("expired compute deadline must reject before parsing");

        assert!(error.contains("connection deadline"));
    }

    #[test]
    fn delta_sidecar_rejects_noncanonical_remote_signature_before_diff() {
        let payload = vec![0x5a; delta_subchunk::DEFAULT_SUBBLOCK_BYTES];
        let candidate = CasChunkRef::from_bytes(0, 0, &payload).expect("candidate chunk");
        let malformed: SubBlockSignature = serde_json::from_value(serde_json::json!({
            "block_size": 0,
            "total_len": payload.len(),
            "blocks": [{
                "weak": 0,
                "strong": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "offset": 0,
                "len": 0
            }]
        }))
        .expect("deserialize hostile signature fixture");
        let states = vec![DeltaChunkSignatureState {
            content_id_hex: candidate.content_id.to_hex(),
            size_bytes: candidate.size_bytes,
            signature: malformed,
        }];

        assert!(receiver_subchunk_signatures_from_states(&[candidate], &states).is_empty());
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

    // ─── Channel bonding: donor leg (`atp bond-donate`) ───────────────────────

    #[test]
    fn bond_subcommands_parse_and_obsolete_static_assignment_flags_fail() {
        let donate = Cli::try_parse_from([
            "atp",
            "bond-donate",
            "/srv/source",
            "--to",
            "127.0.0.1:8473",
            "--rq-allow-unauthenticated-lab",
        ])
        .expect("parse bond-donate");
        assert!(matches!(donate.command, Command::BondDonate(_)));

        let recv = Cli::try_parse_from([
            "atp",
            "bond-recv",
            "/srv/dest",
            "/srv/source",
            "--expect-donors",
            "2",
            "--rq-allow-unauthenticated-lab",
        ])
        .expect("parse bond-recv");
        assert!(matches!(recv.command, Command::BondRecv(_)));

        let pull = Cli::try_parse_from([
            "atp",
            "bond-pull",
            r"C:\shared\payload.bin",
            r"C:\incoming",
            "--donors",
            "wlap",
            "--advertise",
            "100.120.65.94:8473",
            "--remote-atp",
            r"C:\Users\jeffr\.local\bin\atp.exe",
            "--remote-shell",
            "powershell",
            "--rq-allow-unauthenticated-lab",
        ])
        .expect("parse Windows bond-pull");
        let Command::BondPull(pull) = pull.command else {
            panic!("expected bond-pull command");
        };
        assert_eq!(pull.remote_shell, RemoteShell::Powershell);
        assert_eq!(pull.donors, vec!["wlap"]);

        let descriptor = Cli::try_parse_from([
            "atp",
            "__bond-descriptor",
            "/srv/source",
            "--rq-allow-unauthenticated-lab",
        ])
        .expect("parse hidden descriptor command");
        assert!(matches!(descriptor.command, Command::BondDescriptor(_)));

        assert!(
            Cli::try_parse_from([
                "atp",
                "bond-donate",
                "/srv/source",
                "--to",
                "127.0.0.1:8473",
                "--donor-index",
                "0",
                "--donor-count",
                "1",
            ])
            .is_err(),
            "receiver-assigned donor identities must not regain obsolete CLI flags"
        );
    }

    fn bond_test_config() -> RqConfig {
        // Build the same fidelity policy used by the CLI while keeping these
        // descriptor-only tests independent of ATP_RQ_AUTH_KEY_HEX.
        RqConfig {
            symbol_size: DEFAULT_SYMBOL_SIZE,
            max_block_size: AUTO_MAX_BLOCK_SIZE,
            metadata_policy: selected_cli_metadata_policy(),
            preserve_hardlinks: true,
            ..RqConfig::default()
        }
    }

    fn bond_test_try_derive(
        runtime: &asupersync::runtime::Runtime,
        path: &Path,
    ) -> Result<BondTransferDescriptor, String> {
        let source = path.to_path_buf();
        let config = bond_test_config();
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("bond test cx");
            derive_bond_transfer_descriptor(&cx, &source, &config, DEFAULT_MAX_TRANSFER_BYTES, None)
                .await
        }))
    }

    fn bond_test_derive(
        runtime: &asupersync::runtime::Runtime,
        path: &Path,
    ) -> BondTransferDescriptor {
        bond_test_try_derive(runtime, path).expect("derive bonded descriptor")
    }

    fn write_bond_payload(root: &Path, first: &[u8]) {
        fs::create_dir_all(root.join("sub")).expect("payload dirs");
        let paths = [root.join("a.bin"), root.join("sub/b.bin")];
        fs::write(&paths[0], first).expect("write a.bin");
        fs::write(&paths[1], b"second donor file").expect("write b.bin");
        let modified = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        for path in paths {
            fs::File::options()
                .write(true)
                .open(&path)
                .expect("open bond metadata fixture")
                .set_times(fs::FileTimes::new().set_modified(modified))
                .expect("set deterministic bond fixture mtime");
        }
    }

    #[test]
    fn bond_descriptor_derivation_is_deterministic_and_content_addressed() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let root = temp.path().join("payload");
        write_bond_payload(&root, b"hello bonded world");
        // A byte-identical copy at a different absolute path (a second donor's
        // disk) and a tampered copy (a drifted donor).
        let copy = temp.path().join("donor2").join("payload");
        write_bond_payload(&copy, b"hello bonded world");
        fs::File::options()
            .write(true)
            .open(copy.join("a.bin"))
            .expect("open donor with different metadata")
            .set_times(
                fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1_800_000_000)),
            )
            .expect("set divergent donor mtime");
        let tampered = temp.path().join("donor3").join("payload");
        write_bond_payload(&tampered, b"HELLO bonded world");

        let runtime = build_runtime(2).expect("bond test runtime");
        let first = bond_test_derive(&runtime, &root);
        let second = bond_test_derive(&runtime, &root);
        let other_donor = bond_test_derive(&runtime, &copy);
        let drifted = bond_test_derive(&runtime, &tampered);

        assert_eq!(
            first, second,
            "same path twice must derive identical descriptors"
        );
        assert!(
            first.agrees_with(&other_donor),
            "byte-identical copies at different roots and with different platform metadata must agree"
        );
        assert_eq!(first.entry_object_id(0), second.entry_object_id(0));
        assert_eq!(first.entry_object_id(1), other_donor.entry_object_id(1));
        assert_eq!(
            first.transfer_id,
            channel_bonding::transfer_id_hex(
                &first.merkle_root_hex,
                first.total_bytes,
                first.entries.len(),
            ),
            "transfer id must be the rq merkle-derived id"
        );
        assert_eq!(first.entries.len(), 2);
        assert_eq!(first.symbol_size, DEFAULT_SYMBOL_SIZE);
        assert_eq!(first.max_block_size, AUTO_MAX_BLOCK_SIZE as u64);
        let metadata = first
            .metadata
            .as_ref()
            .expect("v4 metadata must be carried");
        assert!(metadata.entries.is_empty());
        assert!(metadata.directories.is_none());

        assert_ne!(
            first.transfer_id, drifted.transfer_id,
            "different bytes must produce a different transfer id"
        );
        assert!(!first.agrees_with(&drifted), "drifted copy must not agree");
        assert_ne!(first.entry_object_id(0), drifted.entry_object_id(0));
    }

    #[test]
    fn bond_descriptor_rejects_unsupported_topology_before_creation() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let runtime = build_runtime(2).expect("bond test runtime");

        let hardlinks = temp.path().join("hardlinks");
        fs::create_dir(&hardlinks).expect("hardlink root");
        fs::write(hardlinks.join("primary.bin"), b"same inode").expect("hardlink primary");
        fs::hard_link(
            hardlinks.join("primary.bin"),
            hardlinks.join("duplicate.bin"),
        )
        .expect("hardlink duplicate");
        let error = bond_test_try_derive(&runtime, &hardlinks)
            .expect_err("RQ bonding must not flatten hardlinks");
        assert!(error.contains("cannot preserve hardlink identity"));

        let empty_tree = temp.path().join("empty-tree");
        fs::create_dir_all(empty_tree.join("nested-empty")).expect("nested empty directory");
        let error = bond_test_try_derive(&runtime, &empty_tree)
            .expect_err("RQ bonding must not flatten nested empty directories");
        assert!(
            error.contains("cannot represent nested empty directories"),
            "unexpected empty-tree rejection: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bond_descriptor_rejects_symlinks_before_creation() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temporary directory");
        let source = temp.path().join("source");
        fs::create_dir(&source).expect("source root");
        fs::write(source.join("target.bin"), b"target").expect("symlink target");
        symlink("target.bin", source.join("link.bin")).expect("source symlink");
        let runtime = build_runtime(2).expect("bond test runtime");
        let error = bond_test_try_derive(&runtime, &source)
            .expect_err("RQ bonding must not flatten symlinks");
        assert!(error.contains("symlink") || error.contains("reparse"));
    }

    /// The CLI no longer constructs donor assignments — the receiver's
    /// enrollment welcome assigns index/count/UDP endpoints server-side — but
    /// the assignment validation the enrollment relies on must keep failing
    /// closed on the same shapes the old CLI flags used to catch.
    #[test]
    fn bond_donor_assignment_validates_index_count_and_auth() {
        use asupersync::net::atp::bonding::{BondAuthKeyRef, DonorAssignment};

        let receiver: SocketAddr = "127.0.0.1:9600".parse().expect("receiver addr");
        let assignment = DonorAssignment::new_static(
            2,
            3,
            vec![receiver],
            Some(BondAuthKeyRef::ControlPlane(
                "rq-auth-sha256:00ff".to_string(),
            )),
        );
        assignment.validate().expect("valid assignment");
        assert_eq!(assignment.donor_index, 2);
        assert_eq!(assignment.donor_count, 3);
        assert_eq!(assignment.receiver_udp_endpoints, vec![receiver]);
        assert!(assignment.requires_symbol_auth());
        assert!(assignment.owns_esi(2), "donor 2 of 3 owns esi 2");
        assert!(!assignment.owns_esi(1), "donor 2 of 3 must not own esi 1");

        let lab = DonorAssignment::new_static(0, 1, vec![receiver], None);
        lab.validate().expect("lab assignment");
        assert!(!lab.requires_symbol_auth());

        // index >= count, zero donors, and counts above the bonding ceiling
        // all fail closed before a single symbol can be sprayed.
        assert!(
            DonorAssignment::new_static(3, 3, vec![receiver], None)
                .validate()
                .is_err()
        );
        assert!(
            DonorAssignment::new_static(0, 0, vec![receiver], None)
                .validate()
                .is_err()
        );
        assert!(
            DonorAssignment::new_static(
                0,
                asupersync::net::atp::bonding::MAX_BONDING_DONORS + 1,
                vec![receiver],
                None,
            )
            .validate()
            .is_err()
        );
        // The same ceiling guards the CLI's --expect-donors surface.
        assert!(validate_bond_expected_donors(0).is_err());
        assert!(validate_bond_expected_donors(1).is_ok());
        assert!(
            validate_bond_expected_donors(asupersync::net::atp::bonding::MAX_BONDING_DONORS + 1)
                .is_err()
        );
    }

    #[test]
    fn bond_auth_key_id_is_a_stable_nonsecret_fingerprint() {
        // High-entropy fixed key (SHA-256 of "test") so AuthKey validation passes.
        let key_hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let upper = key_hex.to_ascii_uppercase();
        let id_a = bond_auth_key_id(Some(key_hex), false).expect("auth key id");
        let id_b =
            bond_auth_key_id(Some(upper.as_str()), false).expect("case-insensitive auth key id");
        assert_eq!(id_a, id_b, "same key bytes must fingerprint identically");

        let id = id_a.expect("authenticated key produces an id");
        assert!(id.starts_with("rq-auth-sha256:"));
        assert!(
            !id.contains(key_hex),
            "fingerprint must never embed the key material"
        );
    }

    #[test]
    fn bond_donate_json_reports_the_donor_leg() {
        let spray = transport_rq::BondedDonorSendReport {
            transfer_id: "tid-bond".to_string(),
            donor_index: 1,
            donor_count: 4,
            receiver_endpoints: vec!["127.0.0.1:9600".parse().expect("receiver addr")],
            entries: 2,
            blocks: 3,
            source_symbols_sent: 10,
            repair_symbols_sent: 5,
            symbols_sent: 15,
            pacing: transport_rq::BondedDonorPacingReport {
                initial_rate_bytes_per_sec: 1_000_000,
                final_rate_bytes_per_sec: 2_000_000,
                burst_symbols: 32,
                burst_bytes: 44_800,
                datagram_bytes: 1_400,
                clean_round0_ramp_enabled: true,
            },
            udp_send_acceleration: transport_rq::UdpSendAccelerationReport::default(),
        };
        // The donor leg now runs the full enrollment + feedback control loop,
        // so the report wraps the round-0 spray with the receiver-assigned
        // identity, served feedback rounds, and the fail-closed receipt.
        let report = transport_rq::BondedDonateReport {
            transfer_id: "tid-bond".to_string(),
            donor_index: 1,
            donor_count: 4,
            feedback_rounds: 2,
            symbols_sent: 21,
            spray,
            receipt: transport_rq::ReceiveReceipt {
                committed: true,
                bytes_received: 96_007,
                files: 1,
                sha_ok: true,
                merkle_ok: true,
                symbols_accepted: 90,
                feedback_rounds: 2,
                reason: None,
                committed_paths: vec!["/tmp/dst/payload.bin".to_string()],
            },
        };

        let json = bond_donate_json(&report, Some(Duration::from_millis(10)));

        assert_eq!(json["event"], "atp_bond_donate");
        assert_eq!(json["transport"], "rq");
        assert_eq!(json["transfer_id"], "tid-bond");
        assert_eq!(json["donor_index"], 1);
        assert_eq!(json["donor_count"], 4);
        assert_eq!(json["feedback_rounds"], 2);
        assert_eq!(json["committed"], true);
        assert_eq!(json["sha_ok"], true);
        assert_eq!(json["merkle_ok"], true);
        assert_eq!(json["receiver_endpoints"][0], "127.0.0.1:9600");
        assert_eq!(json["source_symbols_sent"], 10);
        assert_eq!(json["repair_symbols_sent"], 5);
        assert_eq!(json["round0_symbols_sent"], 15);
        assert_eq!(json["symbols_sent"], 21);
        assert_eq!(json["pacing"]["burst_symbols"], 32);
        assert_eq!(json["pacing"]["clean_round0_ramp_enabled"], true);
        assert_eq!(json["metrics"]["chosen_fanout"], 1);
        assert_eq!(json["metrics"]["symbols_accepted"], 90);
    }

    #[test]
    fn bond_recv_json_reports_enrollment_ingress_and_reallocation() {
        use asupersync::net::atp::bonding::BondedDonorIngressStats;

        let report = transport_rq::BondedReceiveReport {
            transfer_id: "tid-bond".to_string(),
            bytes_received: 200_003,
            files: 1,
            committed: true,
            symbols_accepted: 180,
            feedback_rounds: 2,
            committed_paths: vec![PathBuf::from("/tmp/dst/payload.bin")],
            enrolled_donors: 2,
            reallocated_repair_windows: 7,
            donor_ingress: vec![
                (
                    0,
                    BondedDonorIngressStats {
                        symbols_received: 120,
                        symbols_accepted: 100,
                        duplicate_symbols: 20,
                        source_symbols_accepted: 90,
                        repair_symbols_accepted: 10,
                        symbols_rejected_by_retention: 0,
                    },
                ),
                (
                    1,
                    BondedDonorIngressStats {
                        symbols_received: 90,
                        symbols_accepted: 80,
                        duplicate_symbols: 10,
                        source_symbols_accepted: 60,
                        repair_symbols_accepted: 20,
                        symbols_rejected_by_retention: 0,
                    },
                ),
            ],
        };

        let json = bond_recv_json(&report, 4, Some(Duration::from_millis(25)));

        assert_eq!(json["event"], "atp_bond_receive");
        assert_eq!(json["transport"], "rq");
        assert_eq!(json["committed"], true);
        assert_eq!(json["bytes_received"], 200_003);
        assert_eq!(json["enrolled_donors"], 2);
        assert_eq!(json["reallocated_repair_windows"], 7);
        assert_eq!(json["donor_ingress"][0]["donor_index"], 0);
        assert_eq!(json["donor_ingress"][0]["symbols_accepted"], 100);
        assert_eq!(json["donor_ingress"][1]["donor_index"], 1);
        assert_eq!(json["donor_ingress"][1]["symbols_received"], 90);
        assert_eq!(json["metrics"]["chosen_fanout"], 4);
        assert_eq!(json["committed_paths"][0], "/tmp/dst/payload.bin");
    }

    // ─── Channel bonding: orchestrator (`atp bond-pull`) ──────────────────────

    fn bond_pull_test_args(advertise: Option<SocketAddr>, listen: SocketAddr) -> BondPullArgs {
        BondPullArgs {
            source: "/srv/data/payload.bin".to_string(),
            dest: PathBuf::from("/tmp/dst"),
            donors: vec!["donor@h1".to_string(), "donor@h2".to_string()],
            advertise,
            listen,
            udp_bind: None,
            remote_atp: "atp".to_string(),
            remote_shell: RemoteShell::Auto,
            ssh_options: Vec::new(),
            descriptor_timeout_secs: 300,
            peer_id: "atp-bond-pull".to_string(),
            max_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            workers: 4,
            accept_timeout_secs: DEFAULT_RECV_ACCEPT_TIMEOUT_SECS,
            symbol_size: None,
            max_block_size: MaxBlockSizeArg::Auto,
            repair_overhead: DEFAULT_REPAIR_OVERHEAD,
            rq_auth_key_hex: None,
            rq_allow_unauthenticated_lab: true,
        }
    }

    /// The control address donors dial is never inferred from SSH: explicit
    /// --advertise wins, a routable --listen IP is reused with the real bound
    /// port, and an unspecified listen IP without --advertise fails closed.
    #[test]
    fn bond_pull_control_advertise_is_explicit_and_fails_closed() {
        let explicit: SocketAddr = "192.0.2.7:8473".parse().expect("advertise addr");
        let routable_listen: SocketAddr = "192.0.2.9:0".parse().expect("listen addr");
        let wildcard_listen: SocketAddr = "0.0.0.0:8473".parse().expect("wildcard addr");

        assert_eq!(
            bond_pull_control_advertise(Some(explicit), wildcard_listen, 8473)
                .expect("explicit advertise"),
            explicit
        );
        // Routable --listen: reuse its IP with the actually-bound port
        // (--listen port 0 must still advertise the real port).
        assert_eq!(
            bond_pull_control_advertise(None, routable_listen, 45123)
                .expect("routable listen advertise"),
            "192.0.2.9:45123".parse::<SocketAddr>().expect("addr")
        );
        // Fail closed: wildcard listen with no --advertise.
        assert!(bond_pull_control_advertise(None, wildcard_listen, 8473).is_err());
        // Fail closed: unusable explicit advertise addresses.
        assert!(
            bond_pull_control_advertise(
                Some("0.0.0.0:8473".parse().expect("addr")),
                wildcard_listen,
                8473,
            )
            .is_err()
        );
        assert!(
            bond_pull_control_advertise(
                Some("192.0.2.7:0".parse().expect("addr")),
                wildcard_listen,
                8473,
            )
            .is_err()
        );
    }

    /// The SSH network path is exercised by the in-process loopback e2e
    /// (`bond_cli_two_donor_loopback_commits`); this pins the exact remote
    /// argv `bond-pull` launches per donor and for the descriptor fetch.
    #[test]
    fn bond_pull_remote_argv_carries_control_address_and_agreed_params() {
        let listen: SocketAddr = "0.0.0.0:0".parse().expect("listen addr");
        let control: SocketAddr = "192.0.2.7:8473".parse().expect("control addr");
        let mut args = bond_pull_test_args(Some(control), listen);
        args.symbol_size = Some(1200);
        args.max_block_size = MaxBlockSizeArg::Bytes(128 * 1024);
        args.remote_atp = "/usr/local/bin/atp".to_string();

        let donor = bond_pull_donor_argv(&args, control);
        assert_eq!(
            donor,
            vec![
                "/usr/local/bin/atp".to_string(),
                "bond-donate".to_string(),
                "/srv/data/payload.bin".to_string(),
                "--to".to_string(),
                "192.0.2.7:8473".to_string(),
                "--max-bytes".to_string(),
                DEFAULT_MAX_TRANSFER_BYTES.to_string(),
                "--workers".to_string(),
                "4".to_string(),
                "--max-block-size".to_string(),
                (128 * 1024).to_string(),
                "--repair-overhead".to_string(),
                DEFAULT_REPAIR_OVERHEAD.to_string(),
                "--symbol-size".to_string(),
                "1200".to_string(),
                "--rq-allow-unauthenticated-lab".to_string(),
            ]
        );

        let descriptor = bond_pull_descriptor_argv(&args);
        assert_eq!(
            descriptor,
            vec![
                "/usr/local/bin/atp".to_string(),
                "__bond-descriptor".to_string(),
                "/srv/data/payload.bin".to_string(),
                "--max-bytes".to_string(),
                DEFAULT_MAX_TRANSFER_BYTES.to_string(),
                "--max-block-size".to_string(),
                (128 * 1024).to_string(),
                "--symbol-size".to_string(),
                "1200".to_string(),
                "--rq-allow-unauthenticated-lab".to_string(),
            ]
        );

        // Default surface: no explicit symbol size, authenticated posture —
        // neither optional flag may appear.
        let default_args = bond_pull_test_args(Some(control), listen);
        let mut authed = default_args;
        authed.rq_allow_unauthenticated_lab = false;
        let default_donor = bond_pull_donor_argv(&authed, control);
        assert!(!default_donor.contains(&"--symbol-size".to_string()));
        assert!(
            !default_donor.contains(&"--rq-allow-unauthenticated-lab".to_string()),
            "authenticated pull must not downgrade its donors"
        );
        assert!(
            !default_donor
                .iter()
                .any(|arg| arg.contains("--rq-auth-key-hex")),
            "the auth key travels via {RQ_AUTH_ENV}, never argv"
        );
    }

    /// MANDATORY trio e2e: two in-process donor legs (the exact
    /// `bond_donate_transfer` body `atp bond-donate` runs) feed one in-process
    /// bonded receiver (the exact `bond_recv_serve` body `atp bond-recv` and
    /// `atp bond-pull` run), all on loopback. The commit must be
    /// byte-identical, with BOTH donors enrolled and contributing accepted
    /// symbols. The receiver derives its descriptor from a separate
    /// byte-identical copy, proving the content-addressed agreement the CLI
    /// relies on.
    #[test]
    fn bond_cli_two_donor_loopback_commits() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let payload: Vec<u8> = (0..200_003u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect();
        let donor_a_dir = temp.path().join("donor-a");
        let donor_b_dir = temp.path().join("donor-b");
        let recv_copy_dir = temp.path().join("receiver-copy");
        let dst_dir = temp.path().join("dst");
        for dir in [&donor_a_dir, &donor_b_dir, &recv_copy_dir, &dst_dir] {
            fs::create_dir_all(dir).expect("create e2e dir");
        }
        // Give each replica a stable timestamp even though bonded descriptors
        // intentionally exclude platform metadata: enrollment identity is
        // content/path based so Windows and Unix donors can agree.
        let modified = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        for dir in [&donor_a_dir, &donor_b_dir, &recv_copy_dir] {
            let path = dir.join("payload.bin");
            fs::write(&path, &payload).expect("write e2e payload");
            fs::File::options()
                .write(true)
                .open(&path)
                .expect("open e2e payload")
                .set_times(fs::FileTimes::new().set_modified(modified))
                .expect("set deterministic e2e mtime");
        }

        // The exact CLI config plumbing (`rq_config`) with small blocks so
        // debug-build RaptorQ decode stays fast, tightened drain/accept
        // windows for a loopback lab run.
        let mut config = rq_config(
            DEFAULT_MAX_TRANSFER_BYTES,
            DEFAULT_SYMBOL_SIZE,
            1,
            64 * 1024,
            1.0,
            0.0,
            5,
            None,
            true,
        )
        .expect("bond e2e config");
        config.accept_timeout = Duration::from_secs(30);

        let (ready_tx, ready_rx) = mpsc::channel::<SocketAddr>();
        let receiver = {
            let source = recv_copy_dir.join("payload.bin");
            let dest = dst_dir.clone();
            let config = config.clone();
            thread::spawn(
                move || -> Result<transport_rq::BondedReceiveReport, String> {
                    let runtime = build_runtime(2)?;
                    runtime.block_on(runtime.handle().spawn(async move {
                        let cx = Cx::current().expect("bond e2e receiver cx");
                        let descriptor = derive_bond_transfer_descriptor(
                            &cx,
                            &source,
                            &config,
                            DEFAULT_MAX_TRANSFER_BYTES,
                            None,
                        )
                        .await?;
                        bond_recv_serve(
                            &cx,
                            &descriptor,
                            &dest,
                            "127.0.0.1:0".parse().expect("listen addr"),
                            "127.0.0.1",
                            2,
                            config,
                            "bond-e2e-receiver",
                            Some(ready_tx),
                        )
                        .await
                    }))
                },
            )
        };
        let control = ready_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("bonded receiver bound its control listener");

        let spawn_donor = |source: PathBuf| {
            let config = config.clone();
            thread::spawn(
                move || -> Result<transport_rq::BondedDonateReport, String> {
                    let runtime = build_runtime(2)?;
                    runtime.block_on(runtime.handle().spawn(async move {
                        let cx = Cx::current().expect("bond e2e donor cx");
                        bond_donate_transfer(
                            &cx,
                            &source,
                            control,
                            config,
                            DEFAULT_MAX_TRANSFER_BYTES,
                            None,
                        )
                        .await
                    }))
                },
            )
        };
        let donor_a = spawn_donor(donor_a_dir.join("payload.bin"));
        let donor_b = spawn_donor(donor_b_dir.join("payload.bin"));

        let report_a = donor_a
            .join()
            .expect("donor A thread")
            .expect("donor A succeeds");
        let report_b = donor_b
            .join()
            .expect("donor B thread")
            .expect("donor B succeeds");
        let report = receiver
            .join()
            .expect("receiver thread")
            .expect("bonded receive commits");

        assert!(report.committed, "bonded receive must commit: {report:?}");
        assert_eq!(report.bytes_received, payload.len() as u64);
        assert_eq!(report.files, 1);
        assert_eq!(report.enrolled_donors, 2);
        let received = fs::read(dst_dir.join("payload.bin")).expect("read committed file");
        assert_eq!(received, payload, "commit must be byte-identical");

        // BOTH donors enrolled with distinct receiver-assigned identities and
        // contributed accepted (novel, post-dedup) symbols.
        assert_ne!(report_a.donor_index, report_b.donor_index);
        assert_eq!(report_a.donor_count, 2);
        assert_eq!(report_b.donor_count, 2);
        assert!(report_a.symbols_sent > 0);
        assert!(report_b.symbols_sent > 0);
        assert_eq!(
            report.donor_ingress.len(),
            2,
            "both donors must appear in ingress stats: {:?}",
            report.donor_ingress
        );
        for (donor_index, stats) in &report.donor_ingress {
            assert!(
                stats.symbols_accepted > 0,
                "donor {donor_index} must contribute accepted symbols: {stats:?}"
            );
        }

        // Both donors saw the same fail-closed commit receipt the CLI reports.
        for donor in [&report_a, &report_b] {
            assert!(donor.receipt.committed);
            assert!(donor.receipt.sha_ok && donor.receipt.merkle_ok);
            let json = bond_donate_json(donor, Some(Duration::from_millis(1)));
            assert_eq!(json["committed"], true);
            assert_eq!(json["donor_count"], 2);
        }
        let recv_json = bond_recv_json(&report, 1, Some(Duration::from_millis(1)));
        assert_eq!(recv_json["enrolled_donors"], 2);
        assert_eq!(
            recv_json["donor_ingress"]
                .as_array()
                .expect("ingress array")
                .len(),
            2
        );
    }

    #[test]
    fn bond_source_root_uses_parent_for_files_and_self_for_dirs() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let dir = temp.path().join("tree");
        fs::create_dir_all(&dir).expect("tree dir");
        let file = dir.join("payload.bin");
        fs::write(&file, b"bytes").expect("payload file");

        assert_eq!(bond_source_root(&dir).expect("dir root"), dir);
        assert_eq!(bond_source_root(&file).expect("file root"), dir);
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
#[cfg(unix)]
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

#[cfg(not(unix))]
fn raise_fd_limit() {}

fn main() -> ExitCode {
    raise_fd_limit();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Send(args) => run_send(args),
        Command::Recv(args) => run_recv(args, false),
        Command::Serve(args) => run_recv(args, true),
        Command::BondDonate(args) => run_bond_donate(args),
        Command::BondRecv(args) => run_bond_recv(args),
        Command::BondPull(args) => run_bond_pull(args),
        Command::BondDescriptor(args) => run_bond_descriptor(args),
        Command::RqKeygen => generate_rq_auth_key_hex().map(|key| {
            println!("{key}");
        }),
        Command::DeltaStateExport { dest } => export_delta_state(&dest),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("atp failed: {err}");
            ExitCode::FAILURE
        }
    }
}
