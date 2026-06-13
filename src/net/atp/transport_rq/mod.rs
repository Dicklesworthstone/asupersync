//! ATP-over-RaptorQ transport (v1): the *fast, robust* ATP data plane.
//!
//! Where [`crate::net::atp::transport_tcp`] moves bytes over a single reliable
//! TCP stream, this transport is built for saturating the pipe on a lossy,
//! high-latency internet path:
//!
//! - **Data plane = RaptorQ fountain symbols over UDP.** Each file entry is
//!   erasure-coded ([`crate::raptorq`], RFC 6330 systematic RaptorQ) into source
//!   plus repair symbols. Symbols are *fungible*: any `K (+ε)` of them recover
//!   the entry, from any socket, in any order. Loss is absorbed by repair
//!   symbols instead of head-of-line-blocking retransmits.
//! - **Multi-socket fan-out.** Symbols are sprayed round-robin across `N` UDP
//!   sockets so a single flow's congestion control / per-socket buffer does not
//!   cap throughput.
//! - **Reliable control plane = one TCP connection** reusing the canonical
//!   `AtpFrameCodec`: handshake (transfer id + receiver UDP port + coding
//!   params), the transfer manifest, fountain *NeedMore* feedback, and the final
//!   verified receipt.
//!
//! # Integrity (fail-closed, identical guarantee to `transport_tcp`)
//!
//! After decode, the receiver (1) checks every entry's SHA-256 against the
//! manifest and (2) rebuilds the deterministic flat [`ObjectGraph`] and compares
//! [`MerkleRoot::from_graph`] to the manifest root. Only if both hold does it
//! atomically write the destination and report `committed = true`. Any mismatch,
//! oversize entry, unreachable peer, or undecodable transfer is a hard error.
//!
//! # Fountain feedback loop
//!
//! v1 uses a bounded request/response loop rather than a continuous concurrent
//! ARQ, which keeps it correct on the current runtime:
//!
//! 1. Sender sprays every entry's source symbols + `repair_overhead` extra
//!    repair symbols across the UDP sockets, then sends `ObjectComplete` on TCP.
//! 2. Receiver feeds arriving symbols into a per-entry [`DecodingPipeline`].
//!    On `ObjectComplete` it replies with either a `Proof` receipt (all entries
//!    decoded → verified + committed) or a `NeedMore` list of still-incomplete
//!    entry indices.
//! 3. For each `NeedMore` round the sender generates a *fresh* batch of repair
//!    symbols (higher ESI range — RaptorQ is rateless) for the listed entries
//!    and resprays. Bounded by `max_feedback_rounds`; exhausting them is a hard
//!    error, never a silent partial success.
//!
//! On a low-loss path the initial over-provision means round 0 succeeds; the
//! loop only engages under real loss, which the loopback loss-injection test
//! exercises deterministically.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::atp::manifest::MerkleRoot;
use crate::atp::object::{Object, ObjectEdge, ObjectGraph};
use crate::bytes::BytesMut;
use crate::codec::Decoder;
use crate::cx::Cx;
use crate::decoding::{DecodingConfig, DecodingPipeline, SymbolAcceptResult};
use crate::encoding::EncodingPipeline;
use crate::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use crate::net::atp::protocol::codec::AtpFrameCodec;
use crate::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use crate::net::{TcpListener, TcpStream, UdpBufferConfig, UdpSocket};
use crate::security::authenticated::AuthenticatedSymbol;
use crate::types::resource::{PoolConfig, SymbolPool};
use crate::types::symbol::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};

/// Protocol identifier carried in the handshake; bump on wire-incompatible
/// changes.
pub const ATP_RQ_PROTOCOL: u32 = 1;

/// Magic prefix on every UDP symbol datagram (`"ATRQ"`).
const SYMBOL_MAGIC: u32 = 0x4154_5251;

/// Default RaptorQ symbol payload size.
///
/// Kept small enough that one symbol plus the datagram header stays well under a
/// 1500-byte Ethernet MTU, avoiding IP fragmentation (the worst enemy of a UDP
/// bulk transport).
pub const DEFAULT_SYMBOL_SIZE: u16 = 1024;

/// Default source-block ceiling.
///
/// With 1 KiB symbols this bounds a block at ~8192 source symbols (well under
/// the RFC 6330 K=56403 cap) and lets a single entry span up to 256 blocks (SBN
/// is a `u8`), i.e. up to ~2 GiB per entry.
pub const DEFAULT_MAX_BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// Default fraction of *extra* repair symbols sprayed in round 0, on top of the
/// systematic source symbols (0.15 = +15%).
pub const DEFAULT_REPAIR_OVERHEAD: f64 = 1.15;

/// Default number of UDP sockets the sender sprays across.
pub const DEFAULT_UDP_FANOUT: usize = 4;

/// Default ceiling on a single transfer's total bytes (receiver buffers + decode
/// matrices live in memory in v1).
pub const DEFAULT_MAX_TRANSFER_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Default bound on fountain feedback rounds before failing closed.
pub const DEFAULT_MAX_FEEDBACK_ROUNDS: u32 = 16;

/// UDP datagram header size (magic + transfer tag + entry + sbn + esi + kind +
/// len), big-endian.
const DGRAM_HEADER: usize = 4 + 8 + 4 + 1 + 4 + 1 + 2;

/// Opt-in stderr tracing for transport bring-up/diagnosis. Off unless the
/// `ATP_RQ_TRACE` env var is set, so the production path stays silent.
macro_rules! rqtrace {
    ($($arg:tt)*) => {
        if std::env::var_os("ATP_RQ_TRACE").is_some() {
            eprintln!("[atp-rq] {}", format!($($arg)*));
        }
    };
}

/// Transport tuning knobs.
#[derive(Debug, Clone, Copy)]
pub struct RqConfig {
    /// RaptorQ symbol payload size in bytes.
    pub symbol_size: u16,
    /// Maximum source-block size in bytes.
    pub max_block_size: usize,
    /// Extra repair fraction sprayed in round 0 (>= 1.0).
    pub repair_overhead: f64,
    /// Number of UDP sockets the sender sprays across.
    pub udp_fanout: usize,
    /// Maximum total bytes a single transfer may carry.
    pub max_transfer_bytes: u64,
    /// Maximum fountain feedback rounds before failing closed.
    pub max_feedback_rounds: u32,
    /// Test-only: deterministically drop 1-in-N sprayed source symbols on the
    /// sender to exercise the repair/feedback path. 0 disables.
    pub debug_drop_one_in: u32,
}

impl Default for RqConfig {
    fn default() -> Self {
        Self {
            symbol_size: DEFAULT_SYMBOL_SIZE,
            max_block_size: DEFAULT_MAX_BLOCK_SIZE,
            repair_overhead: DEFAULT_REPAIR_OVERHEAD,
            udp_fanout: DEFAULT_UDP_FANOUT,
            max_transfer_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            max_feedback_rounds: DEFAULT_MAX_FEEDBACK_ROUNDS,
            debug_drop_one_in: 0,
        }
    }
}

/// Errors from the ATP-over-RaptorQ transport.
#[derive(Debug, thiserror::Error)]
pub enum RqError {
    /// Network or local I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Frame codec error.
    #[error("frame error: {0}")]
    Frame(String),
    /// JSON (de)serialization error for a control frame.
    #[error("control frame decode error: {0}")]
    Control(String),
    /// The peer rejected the handshake.
    #[error("handshake rejected by peer: {0}")]
    HandshakeRejected(String),
    /// An unexpected frame type arrived for the current protocol state.
    #[error("unexpected frame: got {got:?}, expected {expected}")]
    Unexpected {
        /// The frame type actually received.
        got: FrameType,
        /// A description of what was expected.
        expected: &'static str,
    },
    /// The transfer exceeded the configured size ceiling.
    #[error("transfer exceeds maximum size ({size} > {max} bytes)")]
    TooLarge {
        /// Declared or observed size.
        size: u64,
        /// Configured maximum.
        max: u64,
    },
    /// RaptorQ encode/decode error.
    #[error("coding error: {0}")]
    Coding(String),
    /// The fountain feedback loop ran out of rounds with entries still
    /// undecoded.
    #[error(
        "transfer did not converge after {rounds} feedback rounds ({pending} entries still incomplete)"
    )]
    NoConvergence {
        /// Feedback rounds attempted.
        rounds: u32,
        /// Entries still undecoded.
        pending: usize,
    },
    /// Integrity verification failed (SHA-256 or merkle-root mismatch).
    #[error("integrity verification failed: {0}")]
    Integrity(String),
    /// The source path was invalid (missing, unsupported type).
    #[error("invalid source path: {0}")]
    Source(String),
    /// The transfer was cancelled via the capability context.
    #[error("transfer cancelled")]
    Cancelled,
}

// ─── Wire control payloads (JSON over TCP) ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Hello {
    protocol: u32,
    role: String,
    peer_id: String,
    symbol_size: u16,
    max_block_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HelloAck {
    accepted: bool,
    peer_id: String,
    /// UDP port the receiver is listening on for symbol datagrams.
    udp_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// One file within a transfer manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Stable index within the transfer (manifest order).
    pub index: u32,
    /// Path relative to the transfer root.
    pub rel_path: String,
    /// Entry size in bytes.
    pub size: u64,
    /// Lowercase hex SHA-256 of the entry content.
    pub sha256_hex: String,
}

/// Transfer manifest carried in the `ObjectManifest` frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferManifest {
    /// Stable transfer identifier (hex).
    pub transfer_id: String,
    /// Name of the transfer root (file name or directory name).
    pub root_name: String,
    /// Whether the root is a directory (vs a single file).
    pub is_directory: bool,
    /// Total bytes across all entries.
    pub total_bytes: u64,
    /// Lowercase hex of `MerkleRoot::from_graph` over the flat object graph.
    pub merkle_root_hex: String,
    /// File entries in manifest order.
    pub entries: Vec<ManifestEntry>,
}

/// Receiver → sender fountain feedback: entries still needing more symbols.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NeedMore {
    /// Entry indices that have not yet decoded.
    pending: Vec<u32>,
}

/// Receipt returned by the receiver in the `Proof` frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiveReceipt {
    /// Whether the receiver atomically committed the transfer to its destination.
    pub committed: bool,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Number of files received.
    pub files: u32,
    /// Whether every entry's SHA-256 matched the manifest.
    pub sha_ok: bool,
    /// Whether the rebuilt merkle root matched the manifest.
    pub merkle_ok: bool,
    /// Total symbol datagrams the receiver accepted.
    pub symbols_accepted: u64,
    /// Fountain feedback rounds used.
    pub feedback_rounds: u32,
    /// Failure reason when `committed` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Absolute destination paths that were committed.
    pub committed_paths: Vec<String>,
}

/// Outcome of a successful [`send_path`] call.
#[derive(Debug, Clone)]
pub struct SendReport {
    /// Transfer identifier.
    pub transfer_id: String,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Number of files sent.
    pub files: u32,
    /// Total symbol datagrams emitted (across all feedback rounds).
    pub symbols_sent: u64,
    /// Fountain feedback rounds used.
    pub feedback_rounds: u32,
    /// Merkle root (hex) of the transfer.
    pub merkle_root_hex: String,
    /// The receiver's receipt.
    pub receipt: ReceiveReceipt,
    /// Peer control-plane address.
    pub peer: SocketAddr,
}

/// Outcome of a successful received transfer.
#[derive(Debug, Clone)]
pub struct ReceiveReport {
    /// Transfer identifier.
    pub transfer_id: String,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Number of files committed.
    pub files: u32,
    /// Whether the transfer was committed to the destination.
    pub committed: bool,
    /// Total symbol datagrams accepted.
    pub symbols_accepted: u64,
    /// Fountain feedback rounds used.
    pub feedback_rounds: u32,
    /// Absolute committed paths.
    pub committed_paths: Vec<PathBuf>,
    /// Peer control-plane address.
    pub peer: SocketAddr,
}

// ─── Frame transport over the TCP control stream ─────────────────────────────

struct FrameTransport<S> {
    stream: S,
    codec: AtpFrameCodec,
    rbuf: BytesMut,
}

impl<S> FrameTransport<S>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    fn new(stream: S) -> Self {
        Self {
            stream,
            codec: AtpFrameCodec::new(),
            rbuf: BytesMut::new(),
        }
    }

    async fn send(&mut self, frame: &Frame) -> Result<(), RqError> {
        let bytes = frame
            .to_wire_bytes()
            .map_err(|e| RqError::Frame(e.to_string()))?;
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Frame, RqError> {
        loop {
            if let Some(frame) = self
                .codec
                .decode(&mut self.rbuf)
                .map_err(|e| RqError::Frame(e.to_string()))?
            {
                return Ok(frame);
            }
            let mut tmp = vec![0u8; 65536];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed control connection mid-transfer",
                )));
            }
            self.rbuf.extend_from_slice(&tmp[..n]);
        }
    }
}

// ─── Helpers (entry walk + merkle, shared definition with transport_tcp) ─────

fn json_frame<T: Serialize>(ty: FrameType, value: &T) -> Result<Frame, RqError> {
    let payload = serde_json::to_vec(value).map_err(|e| RqError::Control(e.to_string()))?;
    Frame::new(ProtocolVersion::CURRENT, ty, payload).map_err(|e| RqError::Frame(e.to_string()))
}

fn parse_json<T: for<'de> Deserialize<'de>>(frame: &Frame) -> Result<T, RqError> {
    serde_json::from_slice(frame.payload()).map_err(|e| RqError::Control(e.to_string()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Build the deterministic flat object graph and return `merkle_root_hex`. This
/// is the *same* construction `transport_tcp` uses (single directory root, edges
/// keyed by relative path, anchored on [`MerkleRoot::from_graph`]); both
/// transports therefore agree on the merkle root for identical content.
fn flat_merkle_root(entries: &[(String, Vec<u8>)]) -> String {
    let mut sorted: Vec<&(String, Vec<u8>)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let mut graph = ObjectGraph::new();
    let mut edges = Vec::with_capacity(sorted.len());
    for (rel_path, bytes) in sorted {
        let obj = Object::file(bytes.clone());
        let id = obj.id.clone();
        if !graph.contains_object(&id) {
            let _ = graph.add_object(obj);
        }
        edges.push(ObjectEdge::new(id, rel_path.clone()));
    }
    let root = Object::directory(edges);
    let _ = graph.add_root(root);
    MerkleRoot::from_graph(&graph).to_hex()
}

/// Derive the per-entry RaptorQ [`ObjectId`] deterministically from the transfer
/// id and entry index, so sender and receiver agree without extra signaling.
fn entry_object_id(transfer_id: &str, index: u32) -> ObjectId {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.entry-object-id.v1\0");
    hasher.update(transfer_id.as_bytes());
    hasher.update(index.to_be_bytes());
    let d = hasher.finalize();
    let high = u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
    let low = u64::from_be_bytes([d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]]);
    ObjectId::new(high, low)
}

/// First 8 bytes of the transfer id hex, as a datagram-tag `u64` (cheap stray
/// packet filter — not a security boundary).
fn transfer_tag(transfer_id: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.tag.v1\0");
    hasher.update(transfer_id.as_bytes());
    let d = hasher.finalize();
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

async fn collect_entries(root: &Path) -> Result<(String, bool, Vec<(String, Vec<u8>)>), RqError> {
    let meta = crate::fs::metadata(root)
        .await
        .map_err(|e| RqError::Source(format!("{}: {e}", root.display())))?;
    let root_name = root.file_name().map_or_else(
        || "transfer".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );

    if meta.is_file() {
        let bytes = crate::fs::read(root)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", root.display())))?;
        return Ok((root_name.clone(), false, vec![(root_name, bytes)]));
    }
    if meta.is_dir() {
        let mut entries = Vec::new();
        collect_dir(root, String::new(), &mut entries).await?;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        return Ok((root_name, true, entries));
    }
    Err(RqError::Source(format!(
        "{}: not a regular file or directory",
        root.display()
    )))
}

fn collect_dir<'a>(
    dir: &'a Path,
    prefix: String,
    out: &'a mut Vec<(String, Vec<u8>)>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RqError>> + Send + 'a>> {
    Box::pin(async move {
        let mut read_dir = crate::fs::read_dir(dir)
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", dir.display())))?;
        let mut children: Vec<(String, PathBuf, bool)> = Vec::new();
        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(|e| RqError::Source(format!("{}: {e}", dir.display())))?
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let ft = entry
                .file_type()
                .await
                .map_err(|e| RqError::Source(format!("{}: {e}", path.display())))?;
            children.push((name, path, ft.is_dir()));
        }
        children.sort_by(|a, b| a.0.cmp(&b.0));

        for (name, path, is_dir) in children {
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if is_dir {
                collect_dir(&path, rel, out).await?;
            } else {
                let bytes = crate::fs::read(&path)
                    .await
                    .map_err(|e| RqError::Source(format!("{}: {e}", path.display())))?;
                out.push((rel, bytes));
            }
        }
        Ok(())
    })
}

/// Join `base` with a forward-slash relative path, rejecting any component that
/// would escape `base`.
fn join_relative(base: &Path, rel: &str) -> Result<PathBuf, RqError> {
    let mut out = base.to_path_buf();
    for component in rel.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." || component.contains('\\') || component.contains(':') {
            return Err(RqError::Source(format!(
                "unsafe path component in entry: {rel}"
            )));
        }
        out.push(component);
    }
    Ok(out)
}

fn transfer_id_hex(merkle_root_hex: &str, total_bytes: u64, file_count: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.rq.transfer-id.v1\0");
    hasher.update(merkle_root_hex.as_bytes());
    hasher.update(total_bytes.to_be_bytes());
    hasher.update((file_count as u64).to_be_bytes());
    hex_encode(&hasher.finalize()[..16])
}

// ─── UDP symbol datagram framing ─────────────────────────────────────────────

fn encode_symbol_datagram(tag: u64, entry: u32, sym: &Symbol) -> Vec<u8> {
    let data = sym.data();
    let mut out = Vec::with_capacity(DGRAM_HEADER + data.len());
    out.extend_from_slice(&SYMBOL_MAGIC.to_be_bytes());
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&entry.to_be_bytes());
    out.push(sym.id().sbn());
    out.extend_from_slice(&sym.id().esi().to_be_bytes());
    out.push(u8::from(sym.kind().is_repair()));
    out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(data);
    out
}

struct ParsedDatagram {
    entry: u32,
    sbn: u8,
    esi: u32,
    kind: SymbolKind,
    payload_len: usize,
    header_len: usize,
}

fn parse_symbol_header(buf: &[u8], expect_tag: u64) -> Option<ParsedDatagram> {
    if buf.len() < DGRAM_HEADER {
        return None;
    }
    if u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) != SYMBOL_MAGIC {
        return None;
    }
    let tag = u64::from_be_bytes([
        buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
    ]);
    if tag != expect_tag {
        return None;
    }
    let entry = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let sbn = buf[16];
    let esi = u32::from_be_bytes([buf[17], buf[18], buf[19], buf[20]]);
    let kind = if buf[21] == 0 {
        SymbolKind::Source
    } else {
        SymbolKind::Repair
    };
    let payload_len = usize::from(u16::from_be_bytes([buf[22], buf[23]]));
    if buf.len() < DGRAM_HEADER + payload_len {
        return None;
    }
    Some(ParsedDatagram {
        entry,
        sbn,
        esi,
        kind,
        payload_len,
        header_len: DGRAM_HEADER,
    })
}

// ─── Per-entry coding state ──────────────────────────────────────────────────

/// Compute the source-symbol count for an entry of `size` bytes given the
/// symbol size (`ceil(size / symbol_size)`, with a 1-symbol floor for empties).
fn source_symbol_count(size: u64, symbol_size: u16) -> usize {
    let s = u64::from(symbol_size.max(1));
    usize::try_from(size.div_ceil(s).max(1)).unwrap_or(usize::MAX)
}

/// Sender-side encoder state for one entry. Holds the bytes so successive
/// feedback rounds can mint fresh repair symbols at ever-higher ESI ranges.
struct EntryEncoder {
    index: u32,
    object_id: ObjectId,
    bytes: Vec<u8>,
}

/// Receiver-side decoder state for one entry.
struct EntryDecoder {
    index: u32,
    object_id: ObjectId,
    size: u64,
    /// `Option` so the completed pipeline can be consumed by `into_data()`.
    pipeline: Option<DecodingPipeline>,
    complete: bool,
    data: Vec<u8>,
}

// ─── Public API: send ────────────────────────────────────────────────────────

/// Transfer the file or directory at `source` to `addr` (the receiver's TCP
/// control address) using RaptorQ symbols over UDP.
///
/// Returns the receiver's verified receipt. Fails closed on an unreachable peer,
/// a rejected handshake, a size-limit breach, a fountain loop that does not
/// converge, or a receiver integrity rejection.
pub async fn send_path(
    cx: &Cx,
    addr: SocketAddr,
    source: &Path,
    config: RqConfig,
    peer_id: &str,
) -> Result<SendReport, RqError> {
    cx.checkpoint().map_err(|_| RqError::Cancelled)?;

    let (root_name, is_directory, entries) = collect_entries(source).await?;
    let total_bytes: u64 = entries.iter().map(|(_, b)| b.len() as u64).sum();
    if total_bytes > config.max_transfer_bytes {
        return Err(RqError::TooLarge {
            size: total_bytes,
            max: config.max_transfer_bytes,
        });
    }

    let merkle_root_hex = flat_merkle_root(&entries);
    let manifest_entries: Vec<ManifestEntry> = entries
        .iter()
        .enumerate()
        .map(|(i, (rel, bytes))| ManifestEntry {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            rel_path: rel.clone(),
            size: bytes.len() as u64,
            sha256_hex: sha256_hex(bytes),
        })
        .collect();
    let transfer_id = transfer_id_hex(&merkle_root_hex, total_bytes, manifest_entries.len());
    let tag = transfer_tag(&transfer_id);
    let manifest = TransferManifest {
        transfer_id: transfer_id.clone(),
        root_name,
        is_directory,
        total_bytes,
        merkle_root_hex: merkle_root_hex.clone(),
        entries: manifest_entries,
    };

    // Control plane: TCP connect + handshake.
    let stream = TcpStream::connect(addr).await?;
    let peer = stream.peer_addr().unwrap_or(addr);
    let mut control = FrameTransport::new(stream);
    control
        .send(&json_frame(
            FrameType::Handshake,
            &Hello {
                protocol: ATP_RQ_PROTOCOL,
                role: "sender".to_string(),
                peer_id: peer_id.to_string(),
                symbol_size: config.symbol_size,
                max_block_size: config.max_block_size as u64,
            },
        )?)
        .await?;
    let ack_frame = control.recv().await?;
    if ack_frame.frame_type() != FrameType::HandshakeAck {
        return Err(RqError::Unexpected {
            got: ack_frame.frame_type(),
            expected: "HandshakeAck",
        });
    }
    let ack: HelloAck = parse_json(&ack_frame)?;
    if !ack.accepted {
        return Err(RqError::HandshakeRejected(
            ack.reason.unwrap_or_else(|| "no reason given".to_string()),
        ));
    }
    rqtrace!("sender: handshake ok, peer udp_port={}", ack.udp_port);

    // Data plane: open UDP sockets connected to the receiver's UDP endpoint.
    let udp_addr = SocketAddr::new(peer.ip(), ack.udp_port);
    let fanout = config.udp_fanout.max(1);
    let local_unspec = if peer.ip().is_ipv4() {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    let mut sockets: Vec<UdpSocket> = Vec::with_capacity(fanout);
    for _ in 0..fanout {
        let sock = UdpSocket::bind(SocketAddr::new(local_unspec, 0)).await?;
        sock.connect(udp_addr).await?;
        // Large send buffer absorbs bursts so the spray loop does not busy-spin
        // on `ENOBUFS`/`WouldBlock` (UDP sockets epoll-report writable even when
        // the send buffer is full).
        let _ = sock.tune_buffers(UdpBufferConfig {
            send_buffer_bytes: Some(16 * 1024 * 1024),
            recv_buffer_bytes: None,
        });
        sockets.push(sock);
    }

    let mut encoders: Vec<EntryEncoder> = entries
        .iter()
        .enumerate()
        .map(|(i, (_, bytes))| {
            let index = u32::try_from(i).unwrap_or(u32::MAX);
            EntryEncoder {
                index,
                object_id: entry_object_id(&transfer_id, index),
                bytes: bytes.clone(),
            }
        })
        .collect();

    // Send the manifest, then spray round 0 (source + overhead repair).
    control
        .send(&json_frame(FrameType::ObjectManifest, &manifest)?)
        .await?;

    let mut symbols_sent: u64 = 0;
    let mut rr = 0usize;
    let mut dropper = 0u32;
    let mut feedback_rounds = 0u32;

    // Round 0: every entry, source symbols + repair_overhead extra.
    let mut pending: BTreeSet<u32> = encoders.iter().map(|e| e.index).collect();
    spray_round(
        cx,
        &mut sockets,
        &mut rr,
        &mut symbols_sent,
        &mut dropper,
        tag,
        &mut encoders,
        &pending,
        config,
        /* esi_base */ 0,
        /* with_source */ true,
    )
    .await?;
    rqtrace!("sender: round 0 sprayed, symbols_sent={symbols_sent}");

    // Feedback loop.
    loop {
        control
            .send(
                &Frame::empty(FrameType::ObjectComplete)
                    .map_err(|e| RqError::Frame(e.to_string()))?,
            )
            .await?;
        rqtrace!("sender: sent ObjectComplete, awaiting reply");
        let reply = control.recv().await?;
        rqtrace!("sender: got reply {:?}", reply.frame_type());
        match reply.frame_type() {
            FrameType::Proof => {
                let receipt: ReceiveReceipt = parse_json(&reply)?;
                let _ = control
                    .send(
                        &Frame::empty(FrameType::Close)
                            .map_err(|e| RqError::Frame(e.to_string()))?,
                    )
                    .await;
                if !receipt.committed {
                    return Err(RqError::Integrity(
                        receipt
                            .reason
                            .clone()
                            .unwrap_or_else(|| "receiver did not commit".to_string()),
                    ));
                }
                return Ok(SendReport {
                    transfer_id,
                    bytes_sent: total_bytes,
                    files: u32::try_from(entries.len()).unwrap_or(u32::MAX),
                    symbols_sent,
                    feedback_rounds,
                    merkle_root_hex,
                    receipt,
                    peer,
                });
            }
            FrameType::ObjectRequest => {
                let need: NeedMore = parse_json(&reply)?;
                feedback_rounds += 1;
                if feedback_rounds > config.max_feedback_rounds {
                    return Err(RqError::NoConvergence {
                        rounds: feedback_rounds,
                        pending: need.pending.len(),
                    });
                }
                pending = need.pending.into_iter().collect();
                if pending.is_empty() {
                    // Receiver says nothing pending but did not send Proof yet;
                    // loop again to fetch the Proof.
                    continue;
                }
                // Fresh repair symbols at a higher ESI base each round.
                let esi_base = source_ceiling(config.symbol_size)
                    .saturating_add(feedback_rounds.saturating_mul(repair_batch(config)));
                spray_round(
                    cx,
                    &mut sockets,
                    &mut rr,
                    &mut symbols_sent,
                    &mut dropper,
                    tag,
                    &mut encoders,
                    &pending,
                    config,
                    esi_base,
                    /* with_source */ false,
                )
                .await?;
            }
            other => {
                return Err(RqError::Unexpected {
                    got: other,
                    expected: "Proof | NeedMore",
                });
            }
        }
    }
}

/// Per-round repair batch size (extra repair symbols minted per entry per
/// feedback round).
fn repair_batch(config: RqConfig) -> u32 {
    // A generous fixed batch keeps convergence fast under loss.
    let s = source_ceiling(config.symbol_size);
    (s / 4).max(16)
}

/// A conservative upper bound on an entry's source ESI range, used to place
/// repair ESIs safely above source ESIs across rounds.
fn source_ceiling(symbol_size: u16) -> u32 {
    let per_block = (DEFAULT_MAX_BLOCK_SIZE / usize::from(symbol_size.max(1))) as u32;
    per_block.saturating_add(1)
}

/// Spray one round of symbols for the `pending` entries across the UDP sockets.
#[allow(clippy::too_many_arguments)]
async fn spray_round(
    cx: &Cx,
    sockets: &mut [UdpSocket],
    rr: &mut usize,
    symbols_sent: &mut u64,
    dropper: &mut u32,
    tag: u64,
    encoders: &mut [EntryEncoder],
    pending: &BTreeSet<u32>,
    config: RqConfig,
    esi_base: u32,
    with_source: bool,
) -> Result<(), RqError> {
    let fanout = sockets.len().max(1);
    for enc in encoders.iter().filter(|e| pending.contains(&e.index)) {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;
        let source_n = source_symbol_count(enc.bytes.len() as u64, config.symbol_size);
        let repair_extra = if with_source {
            ((source_n as f64) * (config.repair_overhead - 1.0)).ceil() as usize
        } else {
            repair_batch(config) as usize
        };
        let repair_count = repair_extra.max(1);

        // Size the pool by per-BLOCK peak, not whole-object: the encoder streams
        // block-by-block (releasing symbols between blocks), so a 1 GiB entry
        // does NOT need a 1 GiB pool. The ceiling is bounded by `max_block_size`
        // regardless of entry size. `max_size = 0` would exhaust on first
        // acquire; `allow_growth` keeps actual allocation tracking real usage up
        // to this ceiling. The 3x covers RFC 6330 intermediate symbols (L > K).
        let symbol_size_usize = usize::from(config.symbol_size.max(1));
        let block_k = config.max_block_size.div_ceil(symbol_size_usize).max(1);
        let pool_max = block_k
            .saturating_mul(3)
            .saturating_add(repair_count)
            .saturating_add(256);
        let pool = SymbolPool::new(PoolConfig {
            symbol_size: config.symbol_size,
            initial_size: source_n.min(block_k).min(1024),
            max_size: pool_max,
            allow_growth: true,
            growth_increment: 256,
        });
        let mut pipeline = EncodingPipeline::new(
            crate::config::EncodingConfig {
                repair_overhead: config.repair_overhead,
                max_block_size: config.max_block_size,
                symbol_size: config.symbol_size,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            pool,
        );

        for encoded in pipeline.encode_with_repair(enc.object_id, &enc.bytes, repair_count) {
            let encoded = encoded.map_err(|e| RqError::Coding(e.to_string()))?;
            let sym = encoded.symbol();
            // Round 0 sends source + repair; feedback rounds send repair only and
            // shift repair ESIs above the source range to avoid re-sending the
            // same symbols.
            if !with_source && sym.kind().is_source() {
                continue;
            }
            let out_sym = if with_source {
                sym.clone()
            } else {
                // Re-home the repair ESI above source so successive rounds are
                // fresh; the receiver only cares that (sbn, esi) is novel.
                let new_esi = esi_base.saturating_add(sym.id().esi());
                Symbol::new(
                    SymbolId::new(sym.id().object_id(), sym.id().sbn(), new_esi),
                    sym.data().to_vec(),
                    SymbolKind::Repair,
                )
            };

            // Test-only deterministic loss injection.
            if config.debug_drop_one_in > 0 {
                *dropper = dropper.wrapping_add(1);
                if *dropper % config.debug_drop_one_in == 0 {
                    continue;
                }
            }

            let dgram = encode_symbol_datagram(tag, enc.index, &out_sym);
            let sock = &mut sockets[*rr % fanout];
            *rr = rr.wrapping_add(1);
            sock.send(&dgram).await?;
            *symbols_sent += 1;

            // Pace: periodically yield so the spray loop cannot monopolize a
            // worker (and so the kernel/loopback path drains between bursts).
            // This also breaks any residual `WouldBlock` busy-spin on a full
            // UDP send buffer.
            if *symbols_sent % 64 == 0 {
                crate::runtime::yield_now().await;
            }
        }
    }
    Ok(())
}

// ─── Public API: receive ─────────────────────────────────────────────────────

/// Accept exactly one transfer (one control connection) on `control_listener`,
/// receiving symbols on a freshly-bound UDP socket, write to `dest_dir`, verify,
/// and return a report.
pub async fn receive_once(
    cx: &Cx,
    control_listener: &TcpListener,
    udp_bind_ip: &str,
    dest_dir: &Path,
    config: RqConfig,
    peer_id: &str,
) -> Result<ReceiveReport, RqError> {
    let (stream, peer) = control_listener.accept().await?;
    receive_connection(cx, stream, peer, udp_bind_ip, dest_dir, config, peer_id).await
}

/// Drive a single accepted control connection through the receive protocol.
pub async fn receive_connection(
    cx: &Cx,
    stream: TcpStream,
    peer: SocketAddr,
    udp_bind_ip: &str,
    dest_dir: &Path,
    config: RqConfig,
    peer_id: &str,
) -> Result<ReceiveReport, RqError> {
    let mut control = FrameTransport::new(stream);

    // Handshake.
    let hello_frame = control.recv().await?;
    if hello_frame.frame_type() != FrameType::Handshake {
        return Err(RqError::Unexpected {
            got: hello_frame.frame_type(),
            expected: "Handshake",
        });
    }
    let hello: Hello = parse_json(&hello_frame)?;
    let accepted = hello.protocol == ATP_RQ_PROTOCOL;

    // Bind the UDP data socket before acking so the sender can spray immediately.
    // Build an owned `SocketAddr` (Copy + 'static) so it satisfies
    // `UdpSocket::bind`'s `'static` address bound and handles IPv6 correctly.
    let bind_ip: std::net::IpAddr = udp_bind_ip
        .parse()
        .map_err(|e| RqError::Source(format!("invalid UDP bind ip '{udp_bind_ip}': {e}")))?;
    let mut udp = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    // Large receive buffer absorbs the sender's symbol burst while the (CPU-bound)
    // RaptorQ decode catches up, so kernel-side drops stay rare.
    let _ = udp.tune_buffers(UdpBufferConfig {
        recv_buffer_bytes: Some(16 * 1024 * 1024),
        send_buffer_bytes: None,
    });
    let udp_port = udp.local_addr()?.port();

    control
        .send(&json_frame(
            FrameType::HandshakeAck,
            &HelloAck {
                accepted,
                peer_id: peer_id.to_string(),
                udp_port,
                reason: if accepted {
                    None
                } else {
                    Some(format!(
                        "unsupported protocol {} (this peer speaks {ATP_RQ_PROTOCOL})",
                        hello.protocol
                    ))
                },
            },
        )?)
        .await?;
    if !accepted {
        return Err(RqError::HandshakeRejected(format!(
            "unsupported protocol {}",
            hello.protocol
        )));
    }

    // Manifest.
    let manifest_frame = control.recv().await?;
    if manifest_frame.frame_type() != FrameType::ObjectManifest {
        return Err(RqError::Unexpected {
            got: manifest_frame.frame_type(),
            expected: "ObjectManifest",
        });
    }
    let manifest: TransferManifest = parse_json(&manifest_frame)?;
    if manifest.total_bytes > config.max_transfer_bytes {
        return Err(RqError::TooLarge {
            size: manifest.total_bytes,
            max: config.max_transfer_bytes,
        });
    }
    let symbol_size = hello.symbol_size;

    // Per-entry decoders.
    let mut decoders: Vec<EntryDecoder> = manifest
        .entries
        .iter()
        .map(|e| {
            let object_id = entry_object_id(&manifest.transfer_id, e.index);
            let dconfig = DecodingConfig {
                symbol_size,
                max_block_size: hello.max_block_size as usize,
                repair_overhead: config.repair_overhead,
                min_overhead: 0,
                max_buffered_symbols: 0,
                block_timeout: std::time::Duration::from_secs(0),
                verify_auth: false,
            };
            let mut pipeline = DecodingPipeline::new(dconfig);
            let params = object_params_for(object_id, e.size, symbol_size, hello.max_block_size);
            // set_object_params failure is a metadata bug, surfaced on first feed.
            if let Err(err) = pipeline.set_object_params(params) {
                rqtrace!(
                    "receiver: entry {} set_object_params FAILED: {err:?} (size={}, blocks={}, k={})",
                    e.index,
                    e.size,
                    params.source_blocks,
                    params.symbols_per_block
                );
            }
            EntryDecoder {
                index: e.index,
                object_id,
                size: e.size,
                pipeline: Some(pipeline),
                complete: e.size == 0,
                data: Vec::new(),
            }
        })
        .collect();

    let tag = transfer_tag(&manifest.transfer_id);
    let mut symbols_accepted: u64 = 0;
    let mut feedback_rounds: u32 = 0;
    let mut rbuf = vec![0u8; usize::from(symbol_size) + DGRAM_HEADER + 64];

    // Drive: alternate between draining UDP symbols and responding to the
    // sender's ObjectComplete on the control channel. We pump UDP between
    // control messages by racing a short-bounded recv against control readiness.
    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;

        // First, drain any control message that is ready (ObjectComplete ends a
        // spray round). We do a blocking control.recv() because the sender only
        // sends ObjectComplete after finishing a spray round, and we have been
        // consuming UDP concurrently via the pump below.
        //
        // To keep v1 correct on the current runtime without a select primitive,
        // we structure it as: pump UDP until the control frame arrives.
        let frame = pump_until_control(
            cx,
            &mut control,
            &mut udp,
            tag,
            &mut rbuf,
            |parsed, payload| {
                if let Some(pos) = decoders.iter().position(|d| d.index == parsed.entry) {
                    if feed_symbol(&mut decoders[pos], parsed, payload, symbol_size) {
                        symbols_accepted += 1;
                    }
                }
            },
        )
        .await?;
        rqtrace!(
            "receiver: pump returned {:?}, symbols_accepted={symbols_accepted}",
            frame.frame_type()
        );

        match frame.frame_type() {
            FrameType::ObjectComplete => {
                // Assemble any entries that just completed.
                for d in &mut decoders {
                    if !d.complete
                        && d.pipeline
                            .as_ref()
                            .is_some_and(DecodingPipeline::is_complete)
                    {
                        if let Some(bytes) = assemble_entry(d) {
                            d.data = bytes;
                            d.complete = true;
                        }
                    }
                }
                let pending: Vec<u32> = decoders
                    .iter()
                    .filter(|d| !d.complete)
                    .map(|d| d.index)
                    .collect();
                rqtrace!(
                    "receiver: ObjectComplete; {} of {} entries still pending",
                    pending.len(),
                    decoders.len()
                );

                if pending.is_empty() {
                    // Verify + commit + Proof.
                    let receipt = verify_and_commit(
                        &manifest,
                        &mut decoders,
                        dest_dir,
                        symbols_accepted,
                        feedback_rounds,
                    )
                    .await?;
                    control
                        .send(&json_frame(FrameType::Proof, &receipt)?)
                        .await?;
                    let _ = control
                        .send(
                            &Frame::empty(FrameType::Close)
                                .map_err(|e| RqError::Frame(e.to_string()))?,
                        )
                        .await;
                    if !receipt.committed {
                        return Err(RqError::Integrity(
                            receipt
                                .reason
                                .unwrap_or_else(|| "verification failed".to_string()),
                        ));
                    }
                    let committed_paths: Vec<PathBuf> =
                        receipt.committed_paths.iter().map(PathBuf::from).collect();
                    return Ok(ReceiveReport {
                        transfer_id: manifest.transfer_id,
                        bytes_received: receipt.bytes_received,
                        files: receipt.files,
                        committed: true,
                        symbols_accepted,
                        feedback_rounds,
                        committed_paths,
                        peer,
                    });
                }

                // Ask for more symbols for the pending entries.
                feedback_rounds += 1;
                if feedback_rounds > config.max_feedback_rounds {
                    let receipt = ReceiveReceipt {
                        committed: false,
                        bytes_received: 0,
                        files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
                        sha_ok: false,
                        merkle_ok: false,
                        symbols_accepted,
                        feedback_rounds,
                        reason: Some(format!(
                            "no convergence after {feedback_rounds} rounds, {} entries pending",
                            pending.len()
                        )),
                        committed_paths: Vec::new(),
                    };
                    let _ = control.send(&json_frame(FrameType::Proof, &receipt)?).await;
                    return Err(RqError::NoConvergence {
                        rounds: feedback_rounds,
                        pending: pending.len(),
                    });
                }
                control
                    .send(&json_frame(
                        FrameType::ObjectRequest,
                        &NeedMore { pending },
                    )?)
                    .await?;
            }
            FrameType::Close => {
                return Err(RqError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "sender closed control before transfer completed",
                )));
            }
            other => {
                return Err(RqError::Unexpected {
                    got: other,
                    expected: "ObjectComplete",
                });
            }
        }
    }
}

/// Feed one received symbol into an entry's decoding pipeline. Returns true if
/// the symbol was a well-formed candidate the pipeline accepted or considered
/// (used only for the accepted-datagram counter, not correctness).
fn feed_symbol(
    dec: &mut EntryDecoder,
    parsed: &ParsedDatagram,
    payload: &[u8],
    symbol_size: u16,
) -> bool {
    if dec.complete {
        return false;
    }
    if payload.len() != usize::from(symbol_size) {
        // RaptorQ symbols are fixed-size; ignore malformed/truncated payloads.
        // (The final block's short tail is zero-padded by the encoder, so all
        // emitted symbols are symbol_size bytes.)
        return false;
    }
    let Some(pipeline) = dec.pipeline.as_mut() else {
        return false;
    };
    let sym = Symbol::new(
        SymbolId::new(dec.object_id, parsed.sbn, parsed.esi),
        payload.to_vec(),
        parsed.kind,
    );
    let auth = AuthenticatedSymbol::new_unauthenticated(sym);
    matches!(
        pipeline.feed(auth),
        Ok(SymbolAcceptResult::BlockComplete { .. }
            | SymbolAcceptResult::Accepted { .. }
            | SymbolAcceptResult::DecodingStarted { .. })
    )
}

/// Assemble a decoded entry's bytes by consuming the completed pipeline.
fn assemble_entry(dec: &mut EntryDecoder) -> Option<Vec<u8>> {
    if dec.size == 0 {
        return Some(Vec::new());
    }
    let pipeline = dec.pipeline.take()?;
    match pipeline.into_data() {
        Ok(mut bytes) => {
            bytes.truncate(usize::try_from(dec.size).unwrap_or(usize::MAX));
            Some(bytes)
        }
        Err(_) => {
            // Re-arm nothing: a failed assemble means we were not actually
            // complete; the entry stays pending and more symbols are requested.
            None
        }
    }
}

fn object_params_for(
    object_id: ObjectId,
    size: u64,
    symbol_size: u16,
    max_block_size: u64,
) -> ObjectParams {
    let max_block = usize::try_from(max_block_size).unwrap_or(DEFAULT_MAX_BLOCK_SIZE);
    let s = usize::from(symbol_size.max(1));
    let total = usize::try_from(size).unwrap_or(0);
    // Mirror the encoder's block plan: greedy max_block_size chunks.
    let mut blocks = 0u16;
    let mut max_k = 0usize;
    if total > 0 {
        let mut offset = 0usize;
        while offset < total {
            let len = (total - offset).min(max_block.max(1));
            let k = len.div_ceil(s);
            max_k = max_k.max(k);
            blocks = blocks.saturating_add(1);
            offset += len;
        }
    }
    ObjectParams::new(
        object_id,
        size,
        symbol_size,
        blocks,
        u16::try_from(max_k).unwrap_or(u16::MAX),
    )
}

/// Verify every entry (SHA-256 + rebuilt merkle root) and, on success, atomically
/// write them to `dest_dir`.
async fn verify_and_commit(
    manifest: &TransferManifest,
    decoders: &mut [EntryDecoder],
    dest_dir: &Path,
    symbols_accepted: u64,
    feedback_rounds: u32,
) -> Result<ReceiveReceipt, RqError> {
    let mut by_index = std::collections::HashMap::new();
    for d in decoders.iter() {
        by_index.insert(d.index, d.data.clone());
    }

    let mut sha_ok = true;
    let mut received: u64 = 0;
    for e in &manifest.entries {
        let data = by_index.get(&e.index);
        match data {
            Some(bytes) => {
                received += bytes.len() as u64;
                if bytes.len() as u64 != e.size || sha256_hex(bytes) != e.sha256_hex {
                    sha_ok = false;
                }
            }
            None => sha_ok = false,
        }
    }

    let rebuilt: Vec<(String, Vec<u8>)> = manifest
        .entries
        .iter()
        .map(|e| {
            (
                e.rel_path.clone(),
                by_index.get(&e.index).cloned().unwrap_or_default(),
            )
        })
        .collect();
    let merkle_ok = flat_merkle_root(&rebuilt) == manifest.merkle_root_hex;

    let committed = sha_ok && merkle_ok;
    let mut committed_paths: Vec<String> = Vec::new();
    if committed {
        let base = dest_dir.join(&manifest.root_name);
        for e in &manifest.entries {
            let bytes = by_index.get(&e.index).cloned().unwrap_or_default();
            let out_path = if manifest.is_directory {
                join_relative(&base, &e.rel_path)?
            } else {
                base.clone()
            };
            if let Some(parent) = out_path.parent() {
                crate::fs::create_dir_all(parent).await?;
            }
            crate::fs::write_atomic(&out_path, &bytes).await?;
            committed_paths.push(out_path.display().to_string());
        }
    }

    Ok(ReceiveReceipt {
        committed,
        bytes_received: received,
        files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
        sha_ok,
        merkle_ok,
        symbols_accepted,
        feedback_rounds,
        reason: if committed {
            None
        } else if !sha_ok {
            Some("per-entry SHA-256 mismatch".to_string())
        } else {
            Some("merkle-root mismatch".to_string())
        },
        committed_paths,
    })
}

/// Pump UDP symbol datagrams into the decoders until a control frame arrives.
///
/// The sender finishes a spray round and *then* sends `ObjectComplete` on TCP,
/// so by interleaving `udp.recv` with `control.recv` we absorb the bulk symbols
/// and return as soon as the round's control marker lands. We use the runtime's
/// `poll_fn`-style readiness on both fds via a manual 2-way poll.
async fn pump_until_control<S, F>(
    cx: &Cx,
    control: &mut FrameTransport<S>,
    udp: &mut UdpSocket,
    tag: u64,
    rbuf: &mut [u8],
    mut on_symbol: F,
) -> Result<Frame, RqError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
    F: FnMut(&ParsedDatagram, &[u8]),
{
    use std::future::poll_fn;
    use std::pin::Pin;
    use std::task::Poll;

    enum Ready {
        Control(usize),
        Udp(usize),
    }

    let mut cbuf = vec![0u8; 65536];
    let pumped: u64 = 0;
    loop {
        cx.checkpoint().map_err(|_| RqError::Cancelled)?;

        // 1) First, non-blockingly drain whatever the control codec already has
        //    buffered (a prior read may have pulled the frame in with symbols).
        if let Some(frame) = control
            .codec
            .decode(&mut control.rbuf)
            .map_err(|e| RqError::Frame(e.to_string()))?
        {
            rqtrace!(
                "pump: returning {:?} after {pumped} udp datagrams",
                frame.frame_type()
            );
            return Ok(frame);
        }

        // 2) Poll both the control stream and the UDP socket once. Whichever is
        //    ready makes progress; if only UDP is ready we keep pumping symbols.
        //    Both register their waker via task_cx, so the task parks until
        //    EITHER fd is ready — a biased two-way select.
        let ready = poll_fn(|task_cx| {
            // UDP first so bulk data drains promptly under load.
            match udp.poll_recv(task_cx, rbuf) {
                Poll::Ready(Ok(n)) => {
                    return Poll::Ready(Ok::<Ready, std::io::Error>(Ready::Udp(n)));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
            let mut read_buf = ReadBuf::new(&mut cbuf);
            match Pin::new(&mut control.stream).poll_read(task_cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(Ready::Control(read_buf.filled().len()))),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        match ready {
            Ready::Udp(n) => {
                if let Some(parsed) = parse_symbol_header(&rbuf[..n], tag) {
                    let start = parsed.header_len;
                    let end = start + parsed.payload_len;
                    if end <= n {
                        on_symbol(&parsed, &rbuf[start..end]);
                    }
                }
            }
            Ready::Control(n) => {
                if n == 0 {
                    return Err(RqError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "control stream closed mid-transfer",
                    )));
                }
                control.rbuf.extend_from_slice(&cbuf[..n]);
                if let Some(frame) = control
                    .codec
                    .decode(&mut control.rbuf)
                    .map_err(|e| RqError::Frame(e.to_string()))?
                {
                    return Ok(frame);
                }
            }
        }
    }
}

/// Run a persistent accept loop, handling each control connection as one
/// receive.
///
/// Returns when the capability context is cancelled. Connection-level errors are
/// reported via `on_result` and do not stop the loop.
pub async fn serve<F>(
    cx: &Cx,
    control_listener: TcpListener,
    udp_bind_ip: String,
    dest_dir: PathBuf,
    config: RqConfig,
    peer_id: String,
    mut on_result: F,
) -> Result<(), RqError>
where
    F: FnMut(Result<ReceiveReport, RqError>),
{
    loop {
        if cx.is_cancel_requested() {
            return Ok(());
        }
        let (stream, peer) = control_listener.accept().await?;
        let result =
            receive_connection(cx, stream, peer, &udp_bind_ip, &dest_dir, config, &peer_id).await;
        on_result(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_roundtrips() {
        let sym = Symbol::new(
            SymbolId::new(ObjectId::new(1, 2), 3, 7),
            vec![9u8; 1024],
            SymbolKind::Repair,
        );
        let dg = encode_symbol_datagram(0xABCD, 42, &sym);
        let parsed = parse_symbol_header(&dg, 0xABCD).expect("parse");
        assert_eq!(parsed.entry, 42);
        assert_eq!(parsed.sbn, 3);
        assert_eq!(parsed.esi, 7);
        assert!(matches!(parsed.kind, SymbolKind::Repair));
        assert_eq!(parsed.payload_len, 1024);
        assert_eq!(
            &dg[parsed.header_len..parsed.header_len + 1024],
            &[9u8; 1024]
        );
    }

    #[test]
    fn datagram_rejects_wrong_tag() {
        let sym = Symbol::new(
            SymbolId::new(ObjectId::new(1, 2), 0, 0),
            vec![0u8; 8],
            SymbolKind::Source,
        );
        let dg = encode_symbol_datagram(0x1111, 0, &sym);
        assert!(parse_symbol_header(&dg, 0x2222).is_none());
    }

    #[test]
    fn datagram_rejects_bad_magic() {
        let mut dg = encode_symbol_datagram(
            0x1111,
            0,
            &Symbol::new(
                SymbolId::new(ObjectId::new(1, 2), 0, 0),
                vec![0u8; 8],
                SymbolKind::Source,
            ),
        );
        dg[0] ^= 0xFF;
        assert!(parse_symbol_header(&dg, 0x1111).is_none());
    }

    #[test]
    fn entry_object_id_is_deterministic_and_index_sensitive() {
        let a = entry_object_id("deadbeef", 0);
        let b = entry_object_id("deadbeef", 0);
        let c = entry_object_id("deadbeef", 1);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn source_symbol_count_has_floor_and_ceils() {
        assert_eq!(source_symbol_count(0, 1024), 1);
        assert_eq!(source_symbol_count(1, 1024), 1);
        assert_eq!(source_symbol_count(1024, 1024), 1);
        assert_eq!(source_symbol_count(1025, 1024), 2);
    }

    #[test]
    fn object_params_match_block_plan() {
        // 3 MiB with 8 MiB blocks => 1 block; 1024-byte symbols => K=3072.
        let p = object_params_for(ObjectId::new(0, 0), 3 * 1024 * 1024, 1024, 8 * 1024 * 1024);
        assert_eq!(p.source_blocks, 1);
        assert_eq!(p.symbols_per_block, 3072);
        // 20 MiB with 8 MiB blocks => 3 blocks (8+8+4).
        let p2 = object_params_for(ObjectId::new(0, 0), 20 * 1024 * 1024, 1024, 8 * 1024 * 1024);
        assert_eq!(p2.source_blocks, 3);
    }
}
