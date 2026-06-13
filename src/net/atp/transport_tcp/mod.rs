//! ATP-over-TCP transport (v1).
//!
//! The first transport that moves real file bytes between machines, verified,
//! over [`crate::net::TcpStream`] / [`crate::net::TcpListener`].
//!
//! This module replaces the CLI/daemon facade documented in
//! `asupersync-qk02uw` (fake sleep-loop progress that opened no socket). It
//! reuses the real ATP building blocks: the canonical `AtpFrameCodec` wire
//! format, the content-addressed [`ObjectGraph`] / [`MerkleRoot`] integrity
//! model, and SHA-256 content hashing.
//!
//! See `docs/atp_tcp_transport_v1.md` for the protocol diagram and rationale
//! (TCP first; native QUIC is a later opt-in transport).
//!
//! # Integrity (fail-closed)
//!
//! The receiver buffers each entry, then (1) compares every entry's SHA-256 to
//! the manifest and (2) rebuilds a deterministic flat [`ObjectGraph`] from the
//! received bytes and compares `MerkleRoot::from_graph` to the manifest root.
//! Only if both hold does it atomically write the destination and report
//! `committed = true`. Any mismatch, short read, oversize entry, unreachable
//! peer, or rejected handshake is a hard error — there is no success path that
//! moves zero bytes.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::atp::manifest::MerkleRoot;
use crate::atp::object::{ContentId, Object, ObjectEdge, ObjectGraph, ObjectId, ObjectKind};
use crate::bytes::BytesMut;
use crate::codec::Decoder;
use crate::cx::Cx;
use crate::io::{AsyncReadExt, AsyncWriteExt};
use crate::net::atp::protocol::codec::AtpFrameCodec;
use crate::net::atp::protocol::frames::{Frame, FrameType, MAX_FRAME_SIZE, ProtocolVersion};
use crate::net::{TcpListener, TcpStream};

/// Protocol identifier carried in the handshake; bump on wire-incompatible
/// changes.
pub const ATP_TCP_PROTOCOL: u32 = 1;

/// Default bulk-data chunk size. Kept comfortably below the 1 MiB
/// `MAX_FRAME_SIZE` so a chunk plus its frame header always fits one frame.
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Default ceiling on a single transfer's total bytes. v1 buffers entries in
/// memory on the receive side, so this also bounds receiver memory.
pub const DEFAULT_MAX_TRANSFER_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Default maximum time to wait for an accepted peer to make protocol progress.
/// The timer is restarted for each control/data frame and receipt write.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Default maximum time a one-shot receiver waits for the initial TCP accept.
/// Persistent `serve()` uses the same value as a cancellation checkpoint cadence.
pub const DEFAULT_ACCEPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of files a single transfer manifest may declare. Bounds the
/// per-entry bookkeeping a remote peer can force the receiver to allocate.
const MAX_MANIFEST_ENTRIES: usize = 4 * 1024 * 1024;

/// Upper bound on the initial receive-buffer capacity reserved per entry. The
/// declared entry size is attacker-controlled, so reservation is capped here and
/// the buffer grows from real bytes (themselves bounded by `max_transfer_bytes`).
const INITIAL_ENTRY_CAPACITY: u64 = 4 * 1024 * 1024;

/// Consecutive `accept()` failures the serve loop tolerates before giving up,
/// so a transient error does not kill a long-running listener while a truly
/// broken listener still terminates instead of hot-looping.
const MAX_CONSECUTIVE_ACCEPT_FAILURES: u32 = 64;

/// Default number of accepted transfers a persistent server may process at
/// once. This bounds child task fan-out while preventing one slow peer from
/// monopolizing the accept loop.
pub const DEFAULT_MAX_ACTIVE_CONNECTIONS: usize = 64;

/// Transport tuning knobs.
#[derive(Debug, Clone, Copy)]
pub struct TransferConfig {
    /// Bulk-data chunk size in bytes.
    pub chunk_size: usize,
    /// Maximum total bytes a single transfer may carry.
    pub max_transfer_bytes: u64,
    /// Maximum time to wait for a connected peer to produce or accept the next
    /// protocol frame before failing the transfer closed.
    pub idle_timeout: Duration,
    /// Maximum time a one-shot receive waits for `accept()`. In persistent
    /// `serve()`, this is a cancellation checkpoint interval while idle.
    pub accept_timeout: Duration,
    /// Maximum number of connections `serve()` may process concurrently.
    /// Values of zero are treated as one active connection.
    pub max_active_connections: usize,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_transfer_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            accept_timeout: DEFAULT_ACCEPT_TIMEOUT,
            max_active_connections: DEFAULT_MAX_ACTIVE_CONNECTIONS,
        }
    }
}

/// Errors from the ATP-over-TCP transport.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
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
    /// Integrity verification failed (SHA-256 or merkle-root mismatch).
    #[error("integrity verification failed: {0}")]
    Integrity(String),
    /// The source path was invalid (missing, unsupported type).
    #[error("invalid source path: {0}")]
    Source(String),
    /// The transfer was cancelled via the capability context.
    #[error("transfer cancelled")]
    Cancelled,
    /// A transport operation exceeded its configured timeout.
    #[error("transport timeout during {operation} after {timeout:?}")]
    Timeout {
        /// Operation that timed out.
        operation: &'static str,
        /// Configured timeout duration.
        timeout: Duration,
    },
}

// ─── Wire control payloads (JSON) ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Hello {
    protocol: u32,
    role: String,
    peer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HelloAck {
    accepted: bool,
    peer_id: String,
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
    /// Merkle root (hex) of the transfer.
    pub merkle_root_hex: String,
    /// The receiver's receipt.
    pub receipt: ReceiveReceipt,
    /// Peer address.
    pub peer: SocketAddr,
}

/// Outcome of a successful [`receive_once`] / served transfer.
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
    /// Absolute committed paths.
    pub committed_paths: Vec<PathBuf>,
    /// Peer address.
    pub peer: SocketAddr,
}

// ─── Frame transport: codec over a byte stream ───────────────────────────────

/// A length-delimited [`Frame`] transport over an async byte stream, using the
/// canonical [`AtpFrameCodec`] wire format.
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

    async fn send(&mut self, frame: &Frame) -> Result<(), TransportError> {
        let bytes = frame
            .to_wire_bytes()
            .map_err(|e| TransportError::Frame(e.to_string()))?;
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Frame, TransportError> {
        loop {
            if let Some(frame) = self
                .codec
                .decode(&mut self.rbuf)
                .map_err(|e| TransportError::Frame(e.to_string()))?
            {
                return Ok(frame);
            }
            let mut tmp = vec![0u8; 65536];
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed connection mid-transfer",
                )));
            }
            self.rbuf.extend_from_slice(&tmp[..n]);
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn json_frame<T: Serialize>(ty: FrameType, value: &T) -> Result<Frame, TransportError> {
    let payload = serde_json::to_vec(value).map_err(|e| TransportError::Control(e.to_string()))?;
    let frame = Frame::new(ProtocolVersion::CURRENT, ty, payload)
        .map_err(|e| TransportError::Frame(e.to_string()))?;
    let encoded_len = frame.encoded_len() as u64;
    if encoded_len > MAX_FRAME_SIZE {
        return Err(TransportError::Frame(format!(
            "{ty:?} JSON frame encodes to {encoded_len} bytes (max {MAX_FRAME_SIZE}); \
             split or chunk the manifest/control payload"
        )));
    }
    Ok(frame)
}

fn parse_json<T: for<'de> Deserialize<'de>>(frame: &Frame) -> Result<T, TransportError> {
    serde_json::from_slice(frame.payload()).map_err(|e| TransportError::Control(e.to_string()))
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

/// Build a deterministic flat object graph over `(rel_path, bytes)` entries and
/// return `(graph, merkle_root_hex)`. The graph is a single directory root whose
/// edges are keyed by full relative path, so the merkle root commits to every
/// file's content and path. Identical builder on both sides ⇒ identical root.
fn build_flat_graph(entries: &[(String, Vec<u8>)]) -> (ObjectGraph, String) {
    let mut sorted: Vec<&(String, Vec<u8>)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let mut graph = ObjectGraph::new();
    let mut edges = Vec::with_capacity(sorted.len());
    for (rel_path, bytes) in sorted {
        let obj = Object::file(bytes.clone());
        let id = obj.id.clone();
        // Content-addressed: identical files share a node; insertion is idempotent.
        if !graph.contains_object(&id) {
            let _ = graph.add_object(obj);
        }
        edges.push(ObjectEdge::new(id, rel_path.clone()));
    }
    let root = Object::directory(edges);
    let _ = graph.add_root(root);
    let merkle = MerkleRoot::from_graph(&graph);
    (graph, merkle.to_hex())
}

struct BorrowedFlatObject<'a> {
    kind: ObjectKind,
    size_bytes: Option<u64>,
    children: Vec<ObjectEdge>,
    content: Option<&'a [u8]>,
}

/// Compute the same flat object-graph merkle root as [`build_flat_graph`]
/// without cloning file contents into an owned [`ObjectGraph`]. The receiver
/// uses this after buffering incoming entries, keeping verification at one
/// buffered copy instead of cloning every entry before hashing.
fn flat_merkle_root_from_slices<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> String {
    let mut sorted: Vec<(&'a str, &'a [u8])> = entries.into_iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));

    let mut objects: BTreeMap<ObjectId, BorrowedFlatObject<'a>> = BTreeMap::new();
    let mut edges = Vec::with_capacity(sorted.len());
    for (rel_path, bytes) in sorted {
        let id = ObjectId::content(ContentId::from_bytes(bytes));
        objects
            .entry(id.clone())
            .or_insert_with(|| BorrowedFlatObject {
                kind: ObjectKind::FileObject,
                size_bytes: Some(bytes.len() as u64),
                children: Vec::new(),
                content: Some(bytes),
            });
        edges.push(ObjectEdge::new(id, rel_path.to_string()));
    }

    let root = Object::directory(edges);
    objects.insert(
        root.id,
        BorrowedFlatObject {
            kind: root.metadata.kind,
            size_bytes: root.metadata.size_bytes,
            children: root.children,
            content: None,
        },
    );

    let mut hasher = Sha256::new();
    for (id, object) in objects {
        hasher.update(id.hash_bytes());
        hasher.update([object.kind as u8]);
        if let Some(size) = object.size_bytes {
            hasher.update(size.to_be_bytes());
        }

        let mut child_indices: Vec<usize> = (0..object.children.len()).collect();
        child_indices.sort_by(|&a, &b| object.children[a].name.cmp(&object.children[b].name));
        for idx in child_indices {
            let edge = &object.children[idx];
            hasher.update(edge.name.as_bytes());
            hasher.update(edge.child_id.hash_bytes());
            hasher.update([u8::from(edge.is_symlink)]);
            if let Some(target) = &edge.symlink_target {
                hasher.update(target.as_os_str().as_encoded_bytes());
            }
        }

        if let Some(content) = object.content {
            let content_hash = Sha256::digest(content);
            hasher.update(content_hash);
        }
    }

    hex_encode(&hasher.finalize())
}

/// Walk a path into `(rel_path, bytes)` entries. A single file yields one entry
/// keyed by its file name; a directory yields one entry per regular file keyed
/// by path relative to the directory.
async fn collect_entries(
    root: &Path,
) -> Result<(String, bool, Vec<(String, Vec<u8>)>), TransportError> {
    let meta = crate::fs::metadata(root)
        .await
        .map_err(|e| TransportError::Source(format!("{}: {e}", root.display())))?;
    let root_name = root.file_name().map_or_else(
        || "transfer".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );

    if meta.is_file() {
        let bytes = crate::fs::read(root)
            .await
            .map_err(|e| TransportError::Source(format!("{}: {e}", root.display())))?;
        return Ok((root_name.clone(), false, vec![(root_name, bytes)]));
    }
    if meta.is_dir() {
        let mut entries = Vec::new();
        collect_dir(root, String::new(), &mut entries).await?;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        return Ok((root_name, true, entries));
    }
    Err(TransportError::Source(format!(
        "{}: not a regular file or directory",
        root.display()
    )))
}

/// Recursive directory walk producing `(rel_path, bytes)` entries with
/// forward-slash relative paths.
fn collect_dir<'a>(
    dir: &'a Path,
    prefix: String,
    out: &'a mut Vec<(String, Vec<u8>)>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), TransportError>> + Send + 'a>> {
    Box::pin(async move {
        let mut read_dir = crate::fs::read_dir(dir)
            .await
            .map_err(|e| TransportError::Source(format!("{}: {e}", dir.display())))?;
        // Collect child names first for deterministic ordering.
        let mut children: Vec<(String, PathBuf, bool)> = Vec::new();
        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(|e| TransportError::Source(format!("{}: {e}", dir.display())))?
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let ft = entry
                .file_type()
                .await
                .map_err(|e| TransportError::Source(format!("{}: {e}", path.display())))?;
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
                    .map_err(|e| TransportError::Source(format!("{}: {e}", path.display())))?;
                out.push((rel, bytes));
            }
        }
        Ok(())
    })
}

/// Validate an incoming transfer manifest's bounds before any receive buffer is
/// allocated. The entry count, the per-entry sizes, and their sum are all
/// attacker-controlled, so a hostile manifest (one entry declaring `u64::MAX`,
/// or millions of entries) must be rejected here rather than allowed to exhaust
/// receiver memory. `total_bytes` is checked too, but it need not match the
/// per-entry sizes, so the declared sum is the load-bearing bound.
fn validate_manifest(
    manifest: &TransferManifest,
    config: &TransferConfig,
) -> Result<(), TransportError> {
    if manifest.total_bytes > config.max_transfer_bytes {
        return Err(TransportError::TooLarge {
            size: manifest.total_bytes,
            max: config.max_transfer_bytes,
        });
    }
    if manifest.entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(TransportError::Frame(format!(
            "manifest declares {} entries (max {MAX_MANIFEST_ENTRIES})",
            manifest.entries.len()
        )));
    }
    if !manifest.is_directory && manifest.entries.len() != 1 {
        return Err(TransportError::Frame(format!(
            "single-file transfer manifest declares {} entries",
            manifest.entries.len()
        )));
    }
    let mut seen_rel_paths = std::collections::BTreeSet::new();
    let declared_total: u64 =
        manifest
            .entries
            .iter()
            .enumerate()
            .try_fold(0u64, |acc, (position, entry)| {
                let expected = u32::try_from(position).map_err(|_| {
                    TransportError::Frame("manifest contains too many indexed entries".to_string())
                })?;
                if entry.index != expected {
                    return Err(TransportError::Frame(format!(
                        "manifest entry index {} does not match position {expected}",
                        entry.index
                    )));
                }
                validate_manifest_rel_path(&entry.rel_path)?;
                if !seen_rel_paths.insert(entry.rel_path.as_str()) {
                    return Err(TransportError::Frame(format!(
                        "duplicate manifest rel_path: {}",
                        entry.rel_path
                    )));
                }
                Ok(acc.saturating_add(entry.size))
            })?;
    if declared_total > config.max_transfer_bytes {
        return Err(TransportError::TooLarge {
            size: declared_total,
            max: config.max_transfer_bytes,
        });
    }
    Ok(())
}

fn validate_manifest_rel_path(rel: &str) -> Result<(), TransportError> {
    if rel.is_empty() || rel.starts_with('/') || rel.starts_with('\\') {
        return Err(TransportError::Source(format!(
            "unsafe manifest rel_path: {rel}"
        )));
    }
    for component in rel.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains('\\')
            || component.contains(':')
        {
            return Err(TransportError::Source(format!(
                "unsafe manifest rel_path: {rel}"
            )));
        }
    }
    Ok(())
}

fn data_frame(index: u32, offset: u64, chunk: &[u8]) -> Result<Frame, TransportError> {
    let mut payload = Vec::with_capacity(12 + chunk.len());
    payload.extend_from_slice(&index.to_be_bytes());
    payload.extend_from_slice(&offset.to_be_bytes());
    payload.extend_from_slice(chunk);
    Frame::new(ProtocolVersion::CURRENT, FrameType::ObjectData, payload)
        .map_err(|e| TransportError::Frame(e.to_string()))
}

fn parse_data_frame(frame: &Frame) -> Result<(u32, u64, &[u8]), TransportError> {
    let p = frame.payload();
    if p.len() < 12 {
        return Err(TransportError::Frame(
            "ObjectData frame shorter than 12-byte header".to_string(),
        ));
    }
    let index = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
    let offset = u64::from_be_bytes([p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11]]);
    Ok((index, offset, &p[12..]))
}

async fn with_transport_timeout<T, E, F>(
    cx: &Cx,
    timeout: Duration,
    operation: &'static str,
    future: F,
) -> Result<T, TransportError>
where
    F: Future<Output = Result<T, E>>,
    TransportError: From<E>,
{
    if timeout.is_zero() {
        return Err(TransportError::Timeout { operation, timeout });
    }
    match crate::time::timeout(cx.now(), timeout, future).await {
        Ok(result) => result.map_err(TransportError::from),
        Err(_elapsed) => Err(TransportError::Timeout { operation, timeout }),
    }
}

type ReceiveTaskHandle = crate::runtime::TaskHandle<Result<ReceiveReport, TransportError>>;

fn receive_task_join_error(err: crate::runtime::JoinError) -> TransportError {
    match err {
        crate::runtime::JoinError::Cancelled(_) => TransportError::Cancelled,
        crate::runtime::JoinError::Panicked(_)
        | crate::runtime::JoinError::PolledAfterCompletion => {
            TransportError::Frame(format!("receive task join failed: {err}"))
        }
    }
}

fn drain_finished_receive_tasks<F>(active: &mut Vec<ReceiveTaskHandle>, on_result: &mut F)
where
    F: FnMut(Result<ReceiveReport, TransportError>),
{
    let mut idx = 0;
    while idx < active.len() {
        if !active[idx].is_finished() {
            idx += 1;
            continue;
        }

        match active[idx].try_join() {
            Ok(Some(result)) => {
                active.swap_remove(idx);
                on_result(result);
            }
            Ok(None) => {
                idx += 1;
            }
            Err(err) => {
                active.swap_remove(idx);
                on_result(Err(receive_task_join_error(err)));
            }
        }
    }
}

async fn abort_and_drain_receive_tasks<F>(
    cx: &Cx,
    active: &mut Vec<ReceiveTaskHandle>,
    on_result: &mut F,
) where
    F: FnMut(Result<ReceiveReport, TransportError>),
{
    for handle in active.iter() {
        handle.abort_with_reason(crate::types::CancelReason::parent_cancelled());
    }
    while let Some(mut handle) = active.pop() {
        match handle.join(cx).await {
            Ok(result) => on_result(result),
            Err(err) => on_result(Err(receive_task_join_error(err))),
        }
    }
}

// ─── Public API: send ────────────────────────────────────────────────────────

/// Transfer the file or directory at `source` to `addr` over a real TCP
/// connection.
///
/// Returns the receiver's verified receipt. Fails closed on an unreachable peer,
/// a rejected handshake, a size-limit breach, or a receiver integrity rejection.
pub async fn send_path(
    cx: &Cx,
    addr: SocketAddr,
    source: &Path,
    config: TransferConfig,
    peer_id: &str,
) -> Result<SendReport, TransportError> {
    cx.checkpoint().map_err(|_| TransportError::Cancelled)?;

    let (root_name, is_directory, entries) = collect_entries(source).await?;
    let total_bytes: u64 = entries.iter().map(|(_, b)| b.len() as u64).sum();
    if total_bytes > config.max_transfer_bytes {
        return Err(TransportError::TooLarge {
            size: total_bytes,
            max: config.max_transfer_bytes,
        });
    }

    let (_, merkle_root_hex) = build_flat_graph(&entries);
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
    let manifest = TransferManifest {
        transfer_id: transfer_id.clone(),
        root_name,
        is_directory,
        total_bytes,
        merkle_root_hex: merkle_root_hex.clone(),
        entries: manifest_entries,
    };

    let stream =
        with_transport_timeout(cx, config.idle_timeout, "connect", TcpStream::connect(addr))
            .await?;
    let peer = stream.peer_addr().unwrap_or(addr);
    let mut transport = FrameTransport::new(stream);

    // Handshake.
    let hello = json_frame(
        FrameType::Handshake,
        &Hello {
            protocol: ATP_TCP_PROTOCOL,
            role: "sender".to_string(),
            peer_id: peer_id.to_string(),
        },
    )?;
    with_transport_timeout(
        cx,
        config.idle_timeout,
        "send handshake",
        transport.send(&hello),
    )
    .await?;
    let ack_frame = with_transport_timeout(
        cx,
        config.idle_timeout,
        "receive handshake ack",
        transport.recv(),
    )
    .await?;
    if ack_frame.frame_type() != FrameType::HandshakeAck {
        return Err(TransportError::Unexpected {
            got: ack_frame.frame_type(),
            expected: "HandshakeAck",
        });
    }
    let ack: HelloAck = parse_json(&ack_frame)?;
    if !ack.accepted {
        return Err(TransportError::HandshakeRejected(
            ack.reason.unwrap_or_else(|| "no reason given".to_string()),
        ));
    }

    // Manifest.
    let manifest_frame = json_frame(FrameType::ObjectManifest, &manifest)?;
    with_transport_timeout(
        cx,
        config.idle_timeout,
        "send manifest",
        transport.send(&manifest_frame),
    )
    .await?;

    // Bulk data, entry by entry.
    for (i, (_, bytes)) in entries.iter().enumerate() {
        cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let mut offset: u64 = 0;
        for chunk in bytes.chunks(config.chunk_size.max(1)) {
            let frame = data_frame(index, offset, chunk)?;
            with_transport_timeout(
                cx,
                config.idle_timeout,
                "send data frame",
                transport.send(&frame),
            )
            .await?;
            offset += chunk.len() as u64;
        }
    }

    // Completion + receipt.
    let complete = Frame::empty(FrameType::ObjectComplete)
        .map_err(|e| TransportError::Frame(e.to_string()))?;
    with_transport_timeout(
        cx,
        config.idle_timeout,
        "send complete",
        transport.send(&complete),
    )
    .await?;
    let receipt_frame =
        with_transport_timeout(cx, config.idle_timeout, "receive proof", transport.recv()).await?;
    if receipt_frame.frame_type() != FrameType::Proof {
        return Err(TransportError::Unexpected {
            got: receipt_frame.frame_type(),
            expected: "Proof receipt",
        });
    }
    let receipt: ReceiveReceipt = parse_json(&receipt_frame)?;

    let close = Frame::empty(FrameType::Close).map_err(|e| TransportError::Frame(e.to_string()))?;
    let _ = with_transport_timeout(
        cx,
        config.idle_timeout,
        "send close",
        transport.send(&close),
    )
    .await;

    if !receipt.committed {
        return Err(TransportError::Integrity(
            receipt
                .reason
                .clone()
                .unwrap_or_else(|| "receiver did not commit".to_string()),
        ));
    }

    Ok(SendReport {
        transfer_id,
        bytes_sent: total_bytes,
        files: u32::try_from(entries.len()).unwrap_or(u32::MAX),
        merkle_root_hex,
        receipt,
        peer,
    })
}

fn transfer_id_hex(merkle_root_hex: &str, total_bytes: u64, file_count: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"asupersync.atp.tcp.transfer-id.v1\0");
    hasher.update(merkle_root_hex.as_bytes());
    hasher.update(total_bytes.to_be_bytes());
    hasher.update((file_count as u64).to_be_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest[..16])
}

// ─── Public API: receive ─────────────────────────────────────────────────────

/// Accept exactly one transfer on `listener`, write it to `dest_dir`, verify it,
/// and return a report. Used by `atp get`'s one-shot receive path and by the
/// daemon's per-connection handler.
pub async fn receive_once(
    cx: &Cx,
    listener: &TcpListener,
    dest_dir: &Path,
    config: TransferConfig,
    peer_id: &str,
) -> Result<ReceiveReport, TransportError> {
    let (stream, peer) =
        with_transport_timeout(cx, config.accept_timeout, "accept", listener.accept()).await?;
    receive_connection(cx, stream, peer, dest_dir, config, peer_id).await
}

/// Drive a single accepted connection through the receive protocol.
pub async fn receive_connection(
    cx: &Cx,
    stream: TcpStream,
    peer: SocketAddr,
    dest_dir: &Path,
    config: TransferConfig,
    peer_id: &str,
) -> Result<ReceiveReport, TransportError> {
    let mut transport = FrameTransport::new(stream);

    // Handshake.
    let hello_frame = with_transport_timeout(
        cx,
        config.idle_timeout,
        "receive handshake",
        transport.recv(),
    )
    .await?;
    if hello_frame.frame_type() != FrameType::Handshake {
        return Err(TransportError::Unexpected {
            got: hello_frame.frame_type(),
            expected: "Handshake",
        });
    }
    let hello: Hello = parse_json(&hello_frame)?;
    let accepted = hello.protocol == ATP_TCP_PROTOCOL;
    let handshake_ack = json_frame(
        FrameType::HandshakeAck,
        &HelloAck {
            accepted,
            peer_id: peer_id.to_string(),
            reason: if accepted {
                None
            } else {
                Some(format!(
                    "unsupported protocol {} (this peer speaks {ATP_TCP_PROTOCOL})",
                    hello.protocol
                ))
            },
        },
    )?;
    with_transport_timeout(
        cx,
        config.idle_timeout,
        "send handshake ack",
        transport.send(&handshake_ack),
    )
    .await?;
    if !accepted {
        return Err(TransportError::HandshakeRejected(format!(
            "unsupported protocol {}",
            hello.protocol
        )));
    }

    // Manifest.
    let manifest_frame = with_transport_timeout(
        cx,
        config.idle_timeout,
        "receive manifest",
        transport.recv(),
    )
    .await?;
    if manifest_frame.frame_type() != FrameType::ObjectManifest {
        return Err(TransportError::Unexpected {
            got: manifest_frame.frame_type(),
            expected: "ObjectManifest",
        });
    }
    let manifest: TransferManifest = parse_json(&manifest_frame)?;
    // The manifest is attacker-controlled — validate its bounds before
    // allocating any receive buffers.
    validate_manifest(&manifest, &config)?;

    // Per-entry receive buffers. Reservation is capped (the declared size is
    // untrusted); each buffer grows from real received bytes.
    let mut buffers: Vec<Vec<u8>> = manifest
        .entries
        .iter()
        .map(|e| {
            let reserve = usize::try_from(e.size.min(INITIAL_ENTRY_CAPACITY)).unwrap_or(0);
            Vec::with_capacity(reserve)
        })
        .collect();
    let mut received: u64 = 0;

    loop {
        cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
        let frame =
            with_transport_timeout(cx, config.idle_timeout, "receive frame", transport.recv())
                .await?;
        match frame.frame_type() {
            FrameType::ObjectData => {
                let (index, offset, chunk) = parse_data_frame(&frame)?;
                let idx = index as usize;
                let entry = manifest.entries.get(idx).ok_or_else(|| {
                    TransportError::Frame(format!("ObjectData for unknown entry index {index}"))
                })?;
                let buf = &mut buffers[idx];
                if offset != buf.len() as u64 {
                    return Err(TransportError::Frame(format!(
                        "ObjectData entry {index} out-of-order: got offset {offset}, expected {}",
                        buf.len()
                    )));
                }
                if buf.len() as u64 + chunk.len() as u64 > entry.size {
                    return Err(TransportError::Frame(format!(
                        "ObjectData entry {index} overruns declared size {}",
                        entry.size
                    )));
                }
                received += chunk.len() as u64;
                if received > config.max_transfer_bytes {
                    return Err(TransportError::TooLarge {
                        size: received,
                        max: config.max_transfer_bytes,
                    });
                }
                buf.extend_from_slice(chunk);
            }
            FrameType::ObjectComplete => break,
            FrameType::Close => break,
            FrameType::Error => {
                return Err(TransportError::Frame(format!(
                    "peer sent Error frame: {}",
                    String::from_utf8_lossy(frame.payload())
                )));
            }
            other => {
                return Err(TransportError::Unexpected {
                    got: other,
                    expected: "ObjectData | ObjectComplete | Close",
                });
            }
        }
    }

    // Verify: per-entry SHA-256 + rebuilt merkle root.
    let mut sha_ok = true;
    for (entry, buf) in manifest.entries.iter().zip(buffers.iter()) {
        if buf.len() as u64 != entry.size || sha256_hex(buf) != entry.sha256_hex {
            sha_ok = false;
            break;
        }
    }
    let rebuilt_root = flat_merkle_root_from_slices(
        manifest
            .entries
            .iter()
            .zip(buffers.iter())
            .map(|(entry, bytes)| (entry.rel_path.as_str(), bytes.as_slice())),
    );
    let merkle_ok = rebuilt_root == manifest.merkle_root_hex;

    let mut committed_paths: Vec<PathBuf> = Vec::new();
    let committed = sha_ok && merkle_ok;
    if committed {
        // Atomic, fully-verified writes into the destination. The base path
        // is sanitized so a hostile `root_name` cannot escape `dest_dir`.
        let base = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
        for (entry, buf) in manifest.entries.iter().zip(buffers.iter()) {
            let out_path = if manifest.is_directory {
                join_relative(&base, &entry.rel_path)?
            } else {
                base.clone()
            };
            if let Some(parent) = out_path.parent() {
                crate::fs::create_dir_all(parent).await?;
            }
            crate::fs::write_atomic(&out_path, buf).await?;
            committed_paths.push(out_path);
        }
    }

    let receipt = ReceiveReceipt {
        committed,
        bytes_received: received,
        files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
        sha_ok,
        merkle_ok,
        reason: if committed {
            None
        } else if !sha_ok {
            Some("per-entry SHA-256 mismatch".to_string())
        } else {
            Some("merkle-root mismatch".to_string())
        },
        committed_paths: committed_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
    };
    let proof = json_frame(FrameType::Proof, &receipt)?;
    with_transport_timeout(
        cx,
        config.idle_timeout,
        "send proof",
        transport.send(&proof),
    )
    .await?;
    let close = Frame::empty(FrameType::Close).map_err(|e| TransportError::Frame(e.to_string()))?;
    let _ = with_transport_timeout(
        cx,
        config.idle_timeout,
        "send close",
        transport.send(&close),
    )
    .await;

    if !committed {
        return Err(TransportError::Integrity(
            receipt
                .reason
                .unwrap_or_else(|| "verification failed".to_string()),
        ));
    }

    Ok(ReceiveReport {
        transfer_id: manifest.transfer_id,
        bytes_received: received,
        files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
        committed,
        committed_paths,
        peer,
    })
}

/// Join `base` with a forward-slash relative path, rejecting any component that
/// would escape `base` (`..`, absolute paths, drive prefixes).
/// Reduce an attacker-controlled `root_name` to a single safe path component
/// joined under `dest_dir`.
///
/// `manifest.root_name` arrives off the wire, and `Path::join` *replaces* the
/// base when its argument is absolute, so `dest_dir.join(&root_name)` with an
/// absolute (or separator-bearing) `root_name` would escape the destination
/// directory entirely — `crate::fs::write_atomic` validates with
/// `allow_absolute = true`, so it would not catch an absolute target. Senders
/// already set `root_name` to a bare file name (see `collect_entries`), so
/// collapsing to the final path component is loss-free for legitimate
/// transfers while fully containing hostile ones.
fn safe_base_for_root_name(dest_dir: &Path, root_name: &str) -> Result<PathBuf, TransportError> {
    if root_name.is_empty() {
        return Err(TransportError::Source(
            "manifest root_name is empty".to_string(),
        ));
    }
    let component = Path::new(root_name)
        .file_name()
        .ok_or_else(|| TransportError::Source(format!("unsafe manifest root_name: {root_name}")))?;
    // `file_name()` never yields `.`/`..`/separators, but guard defensively
    // in case of platform-specific surprises.
    let component_str = component.to_string_lossy();
    if component_str == "."
        || component_str == ".."
        || component_str.contains('/')
        || component_str.contains('\\')
    {
        return Err(TransportError::Source(format!(
            "unsafe manifest root_name: {root_name}"
        )));
    }
    Ok(dest_dir.join(component))
}

fn join_relative(base: &Path, rel: &str) -> Result<PathBuf, TransportError> {
    let mut out = base.to_path_buf();
    for component in rel.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." || component.contains('\\') || component.contains(':') {
            return Err(TransportError::Source(format!(
                "unsafe path component in entry: {rel}"
            )));
        }
        out.push(component);
    }
    Ok(out)
}

/// Run a persistent accept loop, handling each connection as a receive. Returns
/// when the capability context is cancelled. Connection-level errors are
/// reported via `on_result` and do not stop the loop.
pub async fn serve<F>(
    cx: &Cx,
    listener: TcpListener,
    dest_dir: PathBuf,
    config: TransferConfig,
    peer_id: String,
    mut on_result: F,
) -> Result<(), TransportError>
where
    F: FnMut(Result<ReceiveReport, TransportError>),
{
    let mut consecutive_failures: u32 = 0;
    let max_active_connections = config.max_active_connections.max(1);
    let capacity_wait = if config.accept_timeout.is_zero() {
        DEFAULT_ACCEPT_TIMEOUT
    } else {
        config.accept_timeout
    };
    let mut active: Vec<ReceiveTaskHandle> = Vec::new();
    loop {
        drain_finished_receive_tasks(&mut active, &mut on_result);
        if cx.is_cancel_requested() {
            abort_and_drain_receive_tasks(cx, &mut active, &mut on_result).await;
            return Ok(());
        }
        if active.len() >= max_active_connections {
            crate::time::sleep(cx.now(), capacity_wait).await;
            continue;
        }
        let accept =
            with_transport_timeout(cx, config.accept_timeout, "accept", listener.accept()).await;
        match accept {
            Ok((stream, peer)) => {
                consecutive_failures = 0;
                let dest_dir = dest_dir.clone();
                let peer_id = peer_id.clone();
                match cx.spawn(move |child| async move {
                    receive_connection(&child, stream, peer, &dest_dir, config, &peer_id).await
                }) {
                    Ok(handle) => active.push(handle),
                    Err(err) => on_result(Err(TransportError::Frame(format!(
                        "spawn receive task failed: {err}"
                    )))),
                }
            }
            Err(TransportError::Timeout {
                operation: "accept",
                ..
            }) => {
                // No pending connection. Keep the listener alive while giving
                // the loop a bounded cancellation checkpoint.
                consecutive_failures = 0;
            }
            Err(err) => {
                // A transient accept error (e.g. ECONNABORTED, EMFILE) must not
                // tear down a long-running listener, but a persistently broken
                // listener must terminate rather than hot-loop.
                consecutive_failures += 1;
                let message = err.to_string();
                on_result(Err(err));
                if consecutive_failures >= MAX_CONSECUTIVE_ACCEPT_FAILURES {
                    return Err(TransportError::Frame(format!(
                        "accept loop aborted after {consecutive_failures} consecutive failures; \
                         last error: {message}"
                    )));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_graph_is_deterministic_and_order_independent() {
        let a = vec![
            ("a.txt".to_string(), b"alpha".to_vec()),
            ("b.txt".to_string(), b"bravo".to_vec()),
        ];
        let b = vec![
            ("b.txt".to_string(), b"bravo".to_vec()),
            ("a.txt".to_string(), b"alpha".to_vec()),
        ];
        let (_, ra) = build_flat_graph(&a);
        let (_, rb) = build_flat_graph(&b);
        assert_eq!(ra, rb, "merkle root must be independent of entry order");
        assert_eq!(ra.len(), 64, "sha-256 hex root is 64 chars");
    }

    #[test]
    fn borrowed_flat_merkle_root_matches_owned_graph_with_duplicate_content() {
        let entries = vec![
            ("b.txt".to_string(), b"same".to_vec()),
            ("a.txt".to_string(), b"same".to_vec()),
            ("c.txt".to_string(), b"different".to_vec()),
        ];
        let borrowed_root = flat_merkle_root_from_slices(
            entries
                .iter()
                .map(|(rel_path, bytes)| (rel_path.as_str(), bytes.as_slice())),
        );
        let (_, owned_root) = build_flat_graph(&entries);
        assert_eq!(
            borrowed_root, owned_root,
            "borrowed receive-side hashing must preserve the owned ObjectGraph contract"
        );
    }

    #[test]
    fn flat_graph_detects_content_change() {
        let a = vec![("x".to_string(), b"one".to_vec())];
        let b = vec![("x".to_string(), b"two".to_vec())];
        assert_ne!(build_flat_graph(&a).1, build_flat_graph(&b).1);
    }

    #[test]
    fn flat_graph_detects_path_change() {
        let a = vec![("x".to_string(), b"same".to_vec())];
        let b = vec![("y".to_string(), b"same".to_vec())];
        assert_ne!(build_flat_graph(&a).1, build_flat_graph(&b).1);
    }

    #[test]
    fn data_frame_roundtrips() {
        let frame = data_frame(7, 256, b"payload-bytes").unwrap();
        let (index, offset, chunk) = parse_data_frame(&frame).unwrap();
        assert_eq!(index, 7);
        assert_eq!(offset, 256);
        assert_eq!(chunk, b"payload-bytes");
    }

    #[test]
    fn data_frame_rejects_short_header() {
        let frame = Frame::new(
            ProtocolVersion::CURRENT,
            FrameType::ObjectData,
            vec![0, 1, 2],
        )
        .unwrap();
        assert!(parse_data_frame(&frame).is_err());
    }

    #[test]
    fn manifest_json_roundtrips() {
        let manifest = TransferManifest {
            transfer_id: "abc".to_string(),
            root_name: "data".to_string(),
            is_directory: true,
            total_bytes: 9,
            merkle_root_hex: "00".repeat(32),
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: "a/b.txt".to_string(),
                size: 9,
                sha256_hex: "ff".repeat(32),
            }],
        };
        let json = serde_json::to_vec(&manifest).unwrap();
        let back: TransferManifest = serde_json::from_slice(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn json_frame_rejects_oversized_manifest_with_actionable_error() {
        let manifest = TransferManifest {
            transfer_id: "abc".to_string(),
            root_name: "x".repeat(usize::try_from(MAX_FRAME_SIZE).unwrap()),
            is_directory: true,
            total_bytes: 0,
            merkle_root_hex: "00".repeat(32),
            entries: Vec::new(),
        };
        assert!(matches!(
            json_frame(FrameType::ObjectManifest, &manifest),
            Err(TransportError::Frame(msg))
                if msg.contains("ObjectManifest")
                    && msg.contains("split or chunk")
                    && msg.contains("max")
        ));
    }

    #[test]
    fn transfer_config_defaults_bound_accept_and_idle_waits() {
        let cfg = TransferConfig::default();
        assert_eq!(cfg.idle_timeout, DEFAULT_IDLE_TIMEOUT);
        assert_eq!(cfg.accept_timeout, DEFAULT_ACCEPT_TIMEOUT);
        assert_eq!(cfg.max_active_connections, DEFAULT_MAX_ACTIVE_CONNECTIONS);
        assert!(!cfg.idle_timeout.is_zero());
        assert!(!cfg.accept_timeout.is_zero());
        assert!(cfg.max_active_connections > 0);
    }

    #[test]
    fn timeout_error_names_operation_and_duration() {
        let err = TransportError::Timeout {
            operation: "receive frame",
            timeout: Duration::from_secs(60),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("receive frame"));
        assert!(rendered.contains("60s"));
    }

    #[test]
    fn send_path_rejects_zero_idle_timeout_before_connecting() {
        let cx = Cx::for_testing();
        let cfg = TransferConfig {
            idle_timeout: Duration::ZERO,
            ..TransferConfig::default()
        };
        let addr = "127.0.0.1:9".parse().unwrap();
        let result =
            futures_lite::future::block_on(send_path(&cx, addr, Path::new(file!()), cfg, "sender"));

        assert!(matches!(
            result,
            Err(TransportError::Timeout {
                operation: "connect",
                timeout,
            }) if timeout.is_zero()
        ));
    }

    #[test]
    fn receive_task_join_error_preserves_cancellation() {
        let err = receive_task_join_error(crate::runtime::JoinError::Cancelled(
            crate::types::CancelReason::parent_cancelled(),
        ));
        assert!(matches!(err, TransportError::Cancelled));
    }

    #[test]
    fn join_relative_rejects_traversal() {
        let base = Path::new("/tmp/inbox/data");
        assert!(join_relative(base, "../escape").is_err());
        assert!(join_relative(base, "ok/sub/file.txt").is_ok());
        assert_eq!(
            join_relative(base, "ok/sub/file.txt").unwrap(),
            Path::new("/tmp/inbox/data/ok/sub/file.txt")
        );
    }

    #[test]
    fn safe_base_for_root_name_contains_hostile_inputs() {
        let dest = Path::new("/tmp/inbox");
        // Legitimate single-component name is preserved.
        assert_eq!(
            safe_base_for_root_name(dest, "payload").unwrap(),
            Path::new("/tmp/inbox/payload")
        );
        // Absolute root_name would otherwise replace the base via Path::join;
        // it must be collapsed to its final component, contained under dest.
        assert_eq!(
            safe_base_for_root_name(dest, "/etc/cron.d/evil").unwrap(),
            Path::new("/tmp/inbox/evil")
        );
        // Parent-traversal names collapse to a contained component as well.
        assert_eq!(
            safe_base_for_root_name(dest, "../../etc/passwd").unwrap(),
            Path::new("/tmp/inbox/passwd")
        );
        // Names with no usable final component are rejected outright.
        assert!(safe_base_for_root_name(dest, "").is_err());
        assert!(safe_base_for_root_name(dest, "/").is_err());
        assert!(safe_base_for_root_name(dest, "..").is_err());
    }

    fn manifest_with(entries: Vec<ManifestEntry>, total_bytes: u64) -> TransferManifest {
        TransferManifest {
            transfer_id: "t".to_string(),
            root_name: "r".to_string(),
            is_directory: true,
            total_bytes,
            merkle_root_hex: "0".repeat(64),
            entries,
        }
    }

    fn entry(index: u32, size: u64) -> ManifestEntry {
        ManifestEntry {
            index,
            rel_path: format!("f{index}"),
            size,
            sha256_hex: "0".repeat(64),
        }
    }

    #[test]
    fn validate_manifest_accepts_sane_bounds() {
        let m = manifest_with(vec![entry(0, 100), entry(1, 200)], 300);
        assert!(validate_manifest(&m, &TransferConfig::default()).is_ok());
    }

    #[test]
    fn validate_manifest_rejects_lying_entry_size() {
        // total_bytes is small but a single entry declares u64::MAX — the
        // pre-fix code would `Vec::with_capacity(u64::MAX as usize)` and abort.
        let m = manifest_with(vec![entry(0, u64::MAX)], 10);
        assert!(matches!(
            validate_manifest(&m, &TransferConfig::default()),
            Err(TransportError::TooLarge { .. })
        ));
    }

    #[test]
    fn validate_manifest_rejects_declared_sum_over_limit() {
        let cfg = TransferConfig {
            max_transfer_bytes: 1000,
            ..TransferConfig::default()
        };
        let m = manifest_with(vec![entry(0, 600), entry(1, 600)], 1200);
        assert!(matches!(
            validate_manifest(&m, &cfg),
            Err(TransportError::TooLarge { .. })
        ));
    }

    #[test]
    fn validate_manifest_rejects_single_file_with_multiple_entries() {
        let mut m = manifest_with(vec![entry(0, 10), entry(1, 20)], 30);
        m.is_directory = false;
        assert!(matches!(
            validate_manifest(&m, &TransferConfig::default()),
            Err(TransportError::Frame(msg)) if msg.contains("single-file transfer")
        ));
    }

    #[test]
    fn validate_manifest_rejects_duplicate_relative_paths() {
        let mut entries = vec![entry(0, 10), entry(1, 20)];
        entries[1].rel_path = entries[0].rel_path.clone();
        let m = manifest_with(entries, 30);
        assert!(matches!(
            validate_manifest(&m, &TransferConfig::default()),
            Err(TransportError::Frame(msg)) if msg.contains("duplicate manifest rel_path")
        ));
    }

    #[test]
    fn validate_manifest_rejects_nonsequential_indexes() {
        let m = manifest_with(vec![entry(0, 10), entry(7, 20)], 30);
        assert!(matches!(
            validate_manifest(&m, &TransferConfig::default()),
            Err(TransportError::Frame(msg)) if msg.contains("does not match position")
        ));
    }

    #[test]
    fn validate_manifest_rejects_unsafe_relative_paths() {
        for rel_path in [
            "",
            "/abs",
            "../escape",
            "a/../escape",
            "a//b",
            "a\\b",
            "c:drive",
        ] {
            let mut e = entry(0, 10);
            e.rel_path = rel_path.to_string();
            let m = manifest_with(vec![e], 10);
            assert!(
                matches!(
                    validate_manifest(&m, &TransferConfig::default()),
                    Err(TransportError::Source(msg)) if msg.contains("unsafe manifest rel_path")
                ),
                "rel_path {rel_path:?} should fail closed"
            );
        }
    }

    #[test]
    fn sha256_hex_is_lowercase_64() {
        let h = sha256_hex(b"hello world");
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        // Known SHA-256("hello world").
        assert_eq!(
            h,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
