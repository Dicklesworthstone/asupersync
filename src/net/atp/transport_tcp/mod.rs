//! ATP-over-TCP transport (v1).
//!
//! The first transport that moves real file bytes between machines, verified,
//! over [`crate::net::TcpStream`] / [`crate::net::TcpListener`].
//!
//! This module replaces the CLI/daemon facade documented in
//! `asupersync-qk02uw` (fake sleep-loop progress that opened no socket). It
//! reuses the real ATP building blocks: the canonical `AtpFrameCodec` wire
//! format, the content-addressed `ObjectGraph` / `MerkleRoot` integrity model,
//! and SHA-256 content hashing.
//!
//! See `docs/atp_tcp_transport_v1.md` for the protocol diagram and rationale
//! (TCP first; native QUIC is a later opt-in transport).
//!
//! # Memory (bounded / streaming)
//!
//! Neither side ever holds a whole file — let alone the whole transfer — in
//! memory. The sender makes a streaming hash pass over each file, sends the
//! manifest, then re-streams the bytes; the receiver writes each entry straight
//! to a staging file while hashing it incrementally. Peak resident memory is
//! `O(chunk_size)` (default 256 KiB), independent of transfer size.
//!
//! # Integrity (fail-closed)
//!
//! The receiver streams each entry to a per-transfer staging file while hashing
//! it incrementally, then (1) compares every entry's streamed SHA-256 to the
//! manifest and (2) rebuilds the flat object-graph merkle root from the
//! per-entry digests and compares it to the manifest root. Only if both hold
//! does it commit each entry with a per-entry atomic rename or link/create
//! operation and report `committed = true`. Any mismatch, short read, oversize
//! entry, unreachable peer, or rejected handshake is a hard error — there is no
//! success path that moves zero bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::atp::delta::{
    CasChunkRef, ContentAddressedChunkStore as DeltaPlannerStore, DeltaResyncFallbackReason,
    DeltaResyncMode, PersistentChunkManifest, plan_incremental_resync,
};
use crate::atp::object::{ContentId, MetadataPolicy, ObjectId};
use crate::net::atp::transport_common::{
    EntryDigest, EntryMetadata, FileKind, FilterSet, SourceEntry, StagedEntryReceive,
    StreamingError, apply_entry_metadata, collect_entries, flat_merkle_root_from_digests,
    hash_file_streaming, hex_encode, metadata_commitment, read_entry_metadata,
};
// Owned-graph merkle helpers (`build_flat_graph`, `flat_merkle_root_from_slices`)
// are now test-only differential oracles for the streaming digest path, so their
// supporting imports are gated to the test build to keep `-D warnings` clean.
#[cfg(test)]
use crate::atp::manifest::MerkleRoot;
#[cfg(test)]
use crate::atp::object::{Object, ObjectEdge, ObjectGraph};
use crate::bytes::BytesMut;
use crate::codec::Decoder;
use crate::cx::Cx;
use crate::io::{AsyncReadExt, AsyncWriteExt};
use crate::net::atp::protocol::codec::AtpFrameCodec;
use crate::net::atp::protocol::frames::{Frame, FrameType, MAX_FRAME_SIZE, ProtocolVersion};
#[cfg(test)]
use crate::net::atp::transport_common::flat_merkle_root_from_slices;
use crate::net::{TcpListener, TcpStream};

/// Protocol identifier carried in the handshake; bump on wire-incompatible
/// changes.
pub const ATP_TCP_PROTOCOL: u32 = 2;

/// Default bulk-data chunk size. Kept comfortably below the 1 MiB
/// `MAX_FRAME_SIZE` so a chunk plus its frame header always fits one frame.
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// Default ceiling on a single transfer's total bytes.
///
/// Both sides stream to/from disk in fixed `chunk_size` buffers, so this bounds
/// bytes on the wire and on disk, not resident memory (peak RSS is
/// `O(chunk_size)`, not `O(transfer)`).
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

/// Process-unique counter that uniquifies per-transfer staging directory names
/// so concurrent receives of the same `transfer_id` (e.g. the same object from
/// the same peer) never collide on disk.
static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

/// Consecutive `accept()` failures the serve loop tolerates before giving up,
/// so a transient error does not kill a long-running listener while a truly
/// broken listener still terminates instead of hot-looping.
const MAX_CONSECUTIVE_ACCEPT_FAILURES: u32 = 64;

/// Default number of accepted transfers a persistent server may process at
/// once. This bounds child task fan-out while preventing one slow peer from
/// monopolizing the accept loop.
pub const DEFAULT_MAX_ACTIVE_CONNECTIONS: usize = 64;

const DELTA_CHUNK_SCHEMA: &str = "asupersync.atp.tcp.delta-chunk-manifest.v1";

/// Transport tuning knobs.
///
/// Holds a [`MetadataPolicy`] (non-`Copy`), so `TransferConfig` is `Clone`; the
/// persistent `serve()` loop clones it per accepted connection.
#[derive(Debug, Clone)]
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
    /// Filesystem-metadata fidelity policy (mode/mtime/owner/symlinks). Defaults
    /// to [`MetadataPolicy::default`] (`~= rsync -a` minus timestamps); the sender
    /// captures gated metadata into the manifest and the receiver applies it on
    /// commit.
    pub metadata_policy: MetadataPolicy,
    /// Opt-in recreation of special files. When `false` (default, rsync-like),
    /// FIFOs/sockets/devices are skipped and logged. When `true`, FIFOs are
    /// recreated via `mkfifo`; sockets and device nodes are still skipped
    /// (sockets are runtime objects; device nodes need privilege).
    pub allow_special_files: bool,
    /// Opt-in sparse-file reconstruction (rsync `-S`). When `true`, the receiver
    /// punches holes for long zero runs (seeking past them instead of writing),
    /// so a sparse source (e.g. a VM image) stays sparse on disk. Content is
    /// unchanged — the per-entry SHA-256 / merkle still covers the full logical
    /// bytes (holes read back as zeros), so a hole-punching error fails closed.
    pub sparse_files: bool,
    /// Opt-in hardlink preservation (rsync `-H`). When `true`, files that share
    /// an inode within the transfer are sent once (the first by path carries the
    /// content); the receiver `hard_link`s the rest to it instead of writing
    /// duplicate copies. When `false` (default), each is sent and written
    /// independently.
    pub preserve_hardlinks: bool,
    /// Enable the receiver-driven delta planner. When enabled, the sender adds
    /// chunk-level content ids to the manifest and waits for the receiver to
    /// request either a delta chunk set, an already-in-sync no-op, or the legacy
    /// full-object transfer. The receiver falls back to the full path whenever
    /// a safe delta cannot be proven smaller.
    pub enable_delta: bool,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_transfer_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            accept_timeout: DEFAULT_ACCEPT_TIMEOUT,
            max_active_connections: DEFAULT_MAX_ACTIVE_CONNECTIONS,
            metadata_policy: MetadataPolicy::default(),
            allow_special_files: false,
            sparse_files: false,
            preserve_hardlinks: false,
            enable_delta: true,
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

impl From<StreamingError> for TransportError {
    fn from(err: StreamingError) -> Self {
        Self::Source(err.into_message())
    }
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
    /// Entry size in bytes. Symlinks contribute zero content bytes (their target
    /// rides in `metadata`).
    pub size: u64,
    /// Lowercase hex SHA-256 of the entry content.
    pub sha256_hex: String,
    /// Captured filesystem metadata (mode/mtime/owner/symlink) when the sender's
    /// [`MetadataPolicy`] preserves it. Omitted from the wire for a portable
    /// transfer, in which case it deserializes to `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<EntryMetadata>,
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
    /// Independent commitment over per-entry filesystem metadata (sorted by
    /// path), present only when at least one entry carries metadata. The receiver
    /// recomputes and verifies it so metadata-block corruption fails closed, the
    /// same way a content-merkle mismatch does. `None` for a portable transfer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_root_hex: Option<String>,
    /// File entries in manifest order.
    pub entries: Vec<ManifestEntry>,
    /// Optional delta chunk manifest. Old full-transfer behavior remains the
    /// fallback whenever this is absent or the receiver declines the delta path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_manifest: Option<DeltaManifestWire>,
}

/// Sender-side chunk manifest used by receiver-driven delta planning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeltaManifestWire {
    /// Stable schema tag for fail-closed receiver decoding.
    pub schema: String,
    /// Planner tree id. Bound to the transfer root name.
    pub tree_id: String,
    /// Fixed chunk size used to derive all chunk refs.
    pub chunk_size: usize,
    /// Total logical bytes represented by `chunks`.
    pub total_size_bytes: u64,
    /// Planner Merkle root over ordered content-addressed chunks.
    pub merkle_root_hex: String,
    /// Chunk refs in logical transfer order.
    pub chunks: Vec<DeltaChunkWire>,
}

/// One chunk ref in the sender delta manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeltaChunkWire {
    /// Planner chunk index in logical transfer order.
    pub index: u32,
    /// Manifest entry index this chunk belongs to.
    pub entry_index: u32,
    /// Transfer-relative path for diagnostics and receiver assembly.
    pub rel_path: String,
    /// Chunk offset within `rel_path`.
    pub entry_offset: u64,
    /// Chunk offset within the logical transfer stream.
    pub stream_offset: u64,
    /// Chunk length in bytes.
    pub size_bytes: u64,
    /// Hex-encoded domain-separated [`ContentId`] hash for the chunk bytes.
    pub content_id_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DeltaWireMode {
    FullObject,
    DeltaChunks,
    AlreadyInSync,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DeltaObjectRequest {
    mode: DeltaWireMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback_reason: Option<String>,
    sender_merkle_root_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    receiver_merkle_root_hex: Option<String>,
    missing_bytes: u64,
    shared_chunks: u64,
    stale_chunks: u64,
    missing_chunks: Vec<DeltaChunkWire>,
}

impl DeltaObjectRequest {
    fn full(
        sender_merkle_root_hex: impl Into<String>,
        receiver_merkle_root_hex: Option<String>,
        fallback_reason: impl Into<String>,
    ) -> Self {
        Self {
            mode: DeltaWireMode::FullObject,
            fallback_reason: Some(fallback_reason.into()),
            sender_merkle_root_hex: sender_merkle_root_hex.into(),
            receiver_merkle_root_hex,
            missing_bytes: 0,
            shared_chunks: 0,
            stale_chunks: 0,
            missing_chunks: Vec::new(),
        }
    }
}

/// Receipt returned by the receiver in the `Proof` frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiveReceipt {
    /// Whether the receiver committed every integrity-verified entry.
    ///
    /// Individual regular files use atomic rename from staging, but a multi-entry
    /// transfer is not rollback-atomic across all destination paths.
    pub committed: bool,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Number of files received.
    pub files: u32,
    /// Whether every entry's SHA-256 matched the manifest.
    pub sha_ok: bool,
    /// Whether the rebuilt merkle root matched the manifest.
    pub merkle_ok: bool,
    /// Total RaptorQ symbol datagrams accepted by the receiver.
    ///
    /// Plain TCP does not use RaptorQ symbols, so its receipts report zero. QUIC
    /// reuses this schema and populates the counter from its fountain receive path.
    #[serde(default)]
    pub symbols_accepted: u64,
    /// Fountain feedback rounds used by the receiver.
    ///
    /// Plain TCP has no feedback loop, so its receipts report zero.
    #[serde(default)]
    pub feedback_rounds: u32,
    /// Completed RaptorQ decode blocks observed by the receiver.
    ///
    /// Plain TCP does not decode RaptorQ blocks, so its receipts report zero.
    #[serde(default)]
    pub decode_count: u64,
    /// Cumulative receiver-side decode completion time in microseconds.
    ///
    /// Plain TCP does not decode RaptorQ blocks, so its receipts report zero.
    #[serde(default)]
    pub decode_micros: u64,
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
    /// Total RaptorQ symbol datagrams emitted.
    ///
    /// Plain TCP does not use RaptorQ symbols, so it reports zero. QUIC reuses
    /// this schema and populates the counter from its fountain sender path.
    pub symbols_sent: u64,
    /// Fountain feedback rounds used by the sender.
    ///
    /// Plain TCP has no feedback loop, so it reports zero.
    pub feedback_rounds: u32,
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
    /// Total RaptorQ symbol datagrams accepted.
    ///
    /// Plain TCP does not use RaptorQ symbols, so it reports zero. QUIC reuses
    /// this schema and populates the counter from its fountain receive path.
    pub symbols_accepted: u64,
    /// Fountain feedback rounds used by the receiver.
    ///
    /// Plain TCP has no feedback loop, so it reports zero.
    pub feedback_rounds: u32,
    /// Completed RaptorQ decode blocks observed by the receiver.
    ///
    /// Plain TCP does not decode RaptorQ blocks, so it reports zero.
    pub decode_count: u64,
    /// Cumulative receiver-side decode completion time in microseconds.
    ///
    /// Plain TCP does not decode RaptorQ blocks, so it reports zero.
    pub decode_micros: u64,
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

#[cfg(any())]
mod unused_delta_legacy {
    use super::*;

    #[derive(Debug, Clone)]
    struct DeltaTransferBasis {
        manifest: PersistentChunkManifest,
        wire: DeltaManifestWire,
        store: DeltaPlannerStore,
    }

    fn decode_hash_hex(value: &str, label: &str) -> Result<[u8; 32], TransportError> {
        if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(TransportError::Frame(format!(
                "{label} must be a 64-character hex SHA-256/content id"
            )));
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(value, &mut out)
            .map_err(|err| TransportError::Frame(format!("decode {label}: {err}")))?;
        Ok(out)
    }

    fn delta_content_id_from_hex(value: &str) -> Result<ContentId, TransportError> {
        Ok(ContentId::new(decode_hash_hex(
            value,
            "delta content_id_hex",
        )?))
    }

    fn delta_wire_to_manifest(
        wire: &DeltaManifestWire,
    ) -> Result<PersistentChunkManifest, TransportError> {
        if wire.schema != DELTA_CHUNK_SCHEMA {
            return Err(TransportError::Frame(format!(
                "unsupported delta manifest schema: {}",
                wire.schema
            )));
        }
        if wire.tree_id.trim().is_empty() {
            return Err(TransportError::Frame(
                "delta manifest tree_id must not be empty".to_string(),
            ));
        }
        if wire.chunk_size == 0 {
            return Err(TransportError::Frame(
                "delta manifest chunk_size must be greater than zero".to_string(),
            ));
        }
        let mut refs = Vec::with_capacity(wire.chunks.len());
        for chunk in &wire.chunks {
            refs.push(CasChunkRef {
                index: chunk.index,
                byte_offset: chunk.stream_offset,
                size_bytes: chunk.size_bytes,
                content_id: delta_content_id_from_hex(&chunk.content_id_hex)?,
            });
        }
        let manifest = PersistentChunkManifest::new(wire.tree_id.clone(), refs)
            .map_err(|err| TransportError::Frame(format!("invalid delta manifest: {err}")))?;
        if manifest.total_size_bytes != wire.total_size_bytes {
            return Err(TransportError::Frame(format!(
                "delta manifest total size mismatch: wire {}, computed {}",
                wire.total_size_bytes, manifest.total_size_bytes
            )));
        }
        if manifest.merkle_root
            != MerkleRoot::new(decode_hash_hex(
                &wire.merkle_root_hex,
                "delta merkle_root_hex",
            )?)
        {
            return Err(TransportError::Frame(
                "delta manifest Merkle root mismatch".to_string(),
            ));
        }
        Ok(manifest)
    }

    async fn build_delta_basis_from_entries(
        cx: &Cx,
        entries: &[SourceEntry],
        metadatas: &[EntryMetadata],
        tree_id: &str,
        chunk_size: usize,
    ) -> Result<Option<DeltaTransferBasis>, TransportError> {
        if chunk_size == 0 || entries.len() != metadatas.len() {
            return Ok(None);
        }
        if metadatas.iter().any(|metadata| !metadata.is_bare()) {
            return Ok(None);
        }

        let mut store = DeltaPlannerStore::new();
        let mut refs = Vec::new();
        let mut wire_chunks = Vec::new();
        let mut read_buf = vec![0u8; chunk_size];
        let mut stream_offset = 0u64;
        let mut index = 0u32;

        for (entry_index, (entry, metadata)) in entries.iter().zip(metadatas).enumerate() {
            cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
            if !matches!(metadata.file_kind, FileKind::Regular)
                || metadata.hardlink_target.is_some()
            {
                return Ok(None);
            }
            let entry_index = u32::try_from(entry_index).map_err(|_| {
                TransportError::Frame("delta manifest entry index exceeds u32::MAX".to_string())
            })?;
            let mut file = crate::fs::File::open(&entry.abs_path)
                .await
                .map_err(|err| {
                    TransportError::Source(format!("{}: {err}", entry.abs_path.display()))
                })?;
            let mut entry_offset = 0u64;
            loop {
                let n = file.read(&mut read_buf).await.map_err(|err| {
                    TransportError::Source(format!("{}: {err}", entry.abs_path.display()))
                })?;
                if n == 0 {
                    break;
                }
                let chunk = &read_buf[..n];
                let insert = store.insert(chunk).map_err(|err| {
                    TransportError::Frame(format!("delta chunk store insert: {err}"))
                })?;
                let size_bytes = u64::try_from(n)
                    .map_err(|_| TransportError::Frame("delta chunk size overflow".to_string()))?;
                let chunk_ref = CasChunkRef {
                    index,
                    byte_offset: stream_offset,
                    size_bytes,
                    content_id: insert.content_id.clone(),
                };
                wire_chunks.push(DeltaChunkWire {
                    index,
                    entry_index,
                    rel_path: entry.rel_path.clone(),
                    entry_offset,
                    stream_offset,
                    size_bytes,
                    content_id_hex: hex_encode(insert.content_id.hash()),
                });
                refs.push(chunk_ref);
                index = index.checked_add(1).ok_or_else(|| {
                    TransportError::Frame("delta chunk index overflow".to_string())
                })?;
                stream_offset = stream_offset.checked_add(size_bytes).ok_or_else(|| {
                    TransportError::Frame("delta stream offset overflow".to_string())
                })?;
                entry_offset = entry_offset.checked_add(size_bytes).ok_or_else(|| {
                    TransportError::Frame("delta entry offset overflow".to_string())
                })?;
            }
        }

        let manifest = PersistentChunkManifest::new(tree_id.to_string(), refs)
            .map_err(|err| TransportError::Frame(format!("build delta manifest: {err}")))?;
        let wire = DeltaManifestWire {
            schema: DELTA_CHUNK_SCHEMA.to_string(),
            tree_id: tree_id.to_string(),
            chunk_size,
            total_size_bytes: manifest.total_size_bytes,
            merkle_root_hex: manifest.merkle_root.to_hex(),
            chunks: wire_chunks,
        };
        Ok(Some(DeltaTransferBasis {
            manifest,
            wire,
            store,
        }))
    }

    async fn build_delta_basis_for_path(
        cx: &Cx,
        source: &Path,
        config: &TransferConfig,
    ) -> Result<Option<DeltaTransferBasis>, TransportError> {
        let (_, _, entries) = collect_entries(source).await?;
        let mut read_buf = vec![0u8; config.chunk_size.max(1)];
        let mut digests = Vec::with_capacity(entries.len());
        let mut metadatas = Vec::with_capacity(entries.len());
        for entry in &entries {
            cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
            let metadata = read_entry_metadata(&entry.abs_path, &config.metadata_policy).await?;
            if !metadata.is_bare() {
                return Ok(None);
            }
            let (size, content_id, content_sha256) =
                hash_file_streaming(&entry.abs_path, &mut read_buf).await?;
            digests.push(EntryDigest {
                rel_path: entry.rel_path.clone(),
                size,
                content_id,
                content_sha256,
            });
            metadatas.push(metadata);
        }
        let tree_id = flat_merkle_root_from_digests(&digests);
        build_delta_basis_from_entries(cx, &entries, &metadatas, &tree_id, config.chunk_size).await
    }

    fn delta_fallback_reason_text(reason: Option<DeltaResyncFallbackReason>) -> String {
        match reason {
            Some(DeltaResyncFallbackReason::NoReceiverManifest) => "no_receiver_manifest",
            Some(DeltaResyncFallbackReason::ReceiverCasCoverageIncomplete) => {
                "receiver_cas_coverage_incomplete"
            }
            Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject) => {
                "delta_not_smaller_than_full_object"
            }
            None => "delta_planner_selected_full_object",
        }
        .to_string()
    }

    fn delta_request_from_plan(
        mode: DeltaResyncMode,
        fallback_reason: Option<DeltaResyncFallbackReason>,
        sender_merkle_root: &MerkleRoot,
        receiver_merkle_root: Option<&MerkleRoot>,
        missing_bytes: u64,
        shared_chunks: u64,
        stale_chunks: usize,
        missing_chunks: &[CasChunkRef],
        wire: &DeltaManifestWire,
    ) -> Result<DeltaObjectRequest, TransportError> {
        if matches!(mode, DeltaResyncMode::FullObjectFallback) {
            return Ok(DeltaObjectRequest::full(
                sender_merkle_root.to_hex(),
                receiver_merkle_root.map(MerkleRoot::to_hex),
                delta_fallback_reason_text(fallback_reason),
            ));
        }

        let by_index: BTreeMap<u32, &DeltaChunkWire> = wire
            .chunks
            .iter()
            .map(|chunk| (chunk.index, chunk))
            .collect();
        let mut requested = Vec::with_capacity(missing_chunks.len());
        for chunk in missing_chunks {
            let Some(wire_chunk) = by_index.get(&chunk.index) else {
                return Err(TransportError::Frame(format!(
                    "delta planner requested unknown chunk index {}",
                    chunk.index
                )));
            };
            if wire_chunk.size_bytes != chunk.size_bytes
                || wire_chunk.stream_offset != chunk.byte_offset
                || wire_chunk.content_id_hex != hex_encode(chunk.content_id.hash())
            {
                return Err(TransportError::Frame(format!(
                    "delta planner chunk {} does not match wire manifest",
                    chunk.index
                )));
            }
            requested.push((*wire_chunk).clone());
        }

        Ok(DeltaObjectRequest {
            mode: match mode {
                DeltaResyncMode::AlreadyInSync => DeltaWireMode::AlreadyInSync,
                DeltaResyncMode::DeltaChunks => DeltaWireMode::DeltaChunks,
                DeltaResyncMode::FullObjectFallback => DeltaWireMode::FullObject,
            },
            fallback_reason: None,
            sender_merkle_root_hex: sender_merkle_root.to_hex(),
            receiver_merkle_root_hex: receiver_merkle_root.map(MerkleRoot::to_hex),
            missing_bytes,
            shared_chunks,
            stale_chunks: stale_chunks as u64,
            missing_chunks: requested,
        })
    }

    async fn receiver_delta_request(
        cx: &Cx,
        dest_dir: &Path,
        manifest: &TransferManifest,
        config: &TransferConfig,
    ) -> Result<(DeltaObjectRequest, Option<DeltaTransferBasis>), TransportError> {
        let Some(delta_wire) = manifest.delta_manifest.as_ref() else {
            return Ok((
                DeltaObjectRequest::full(&manifest.merkle_root_hex, None, "delta_manifest_absent"),
                None,
            ));
        };
        if !config.enable_delta {
            return Ok((
                DeltaObjectRequest::full(&delta_wire.merkle_root_hex, None, "delta_disabled"),
                None,
            ));
        }

        let target_manifest = delta_wire_to_manifest(delta_wire)?;
        let prior_path = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
        match crate::fs::metadata(&prior_path).await {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok((
                    DeltaObjectRequest::full(
                        target_manifest.merkle_root.to_hex(),
                        None,
                        "no_receiver_manifest",
                    ),
                    None,
                ));
            }
            Err(err) => {
                return Ok((
                    DeltaObjectRequest::full(
                        target_manifest.merkle_root.to_hex(),
                        None,
                        format!("receiver_prior_state_unreadable: {err}"),
                    ),
                    None,
                ));
            }
        }

        let Some(prior_basis) = build_delta_basis_for_path(cx, &prior_path, config).await? else {
            return Ok((
                DeltaObjectRequest::full(
                    target_manifest.merkle_root.to_hex(),
                    None,
                    "receiver_prior_state_not_delta_safe",
                ),
                None,
            ));
        };
        let plan = plan_incremental_resync(
            &target_manifest,
            Some(&prior_basis.manifest),
            &prior_basis.store,
        );
        let request = delta_request_from_plan(
            plan.mode,
            plan.fallback_reason,
            &plan.sender_merkle_root,
            plan.receiver_merkle_root.as_ref(),
            plan.missing_bytes,
            plan.shared_chunks,
            plan.stale_chunks.len(),
            &plan.missing_chunks,
            delta_wire,
        )?;
        let prior = matches!(
            request.mode,
            DeltaWireMode::DeltaChunks | DeltaWireMode::AlreadyInSync
        )
        .then_some(prior_basis);
        Ok((request, prior))
    }

    fn delta_receive_uses_staging(request: &DeltaObjectRequest) -> bool {
        matches!(
            request.mode,
            DeltaWireMode::DeltaChunks | DeltaWireMode::AlreadyInSync
        )
    }

    fn delta_entry_path(
        root: &Path,
        root_is_directory: bool,
        rel_path: &str,
    ) -> Result<PathBuf, TransportError> {
        if root_is_directory {
            join_relative(root, rel_path)
        } else {
            Ok(root.to_path_buf())
        }
    }

    async fn read_delta_chunk_from_root(
        root: &Path,
        root_is_directory: bool,
        chunk: &DeltaChunkWire,
    ) -> Result<Vec<u8>, TransportError> {
        let path = delta_entry_path(root, root_is_directory, &chunk.rel_path)?;
        let len = usize::try_from(chunk.size_bytes).map_err(|_| {
            TransportError::Frame("delta baseline chunk size exceeds usize::MAX".to_string())
        })?;
        let mut file = crate::fs::File::open(&path)
            .await
            .map_err(|err| TransportError::Source(format!("{}: {err}", path.display())))?;
        file.seek(SeekFrom::Start(chunk.entry_offset)).await?;
        let mut bytes = vec![0u8; len];
        file.read_exact(&mut bytes)
            .await
            .map_err(|err| TransportError::Source(format!("{}: {err}", path.display())))?;
        let observed = ContentId::from_bytes(&bytes).to_hex();
        if observed != chunk.content_id_hex {
            return Err(TransportError::Integrity(format!(
                "delta baseline chunk hash drift for {} at offset {}",
                chunk.rel_path, chunk.entry_offset
            )));
        }
        Ok(bytes)
    }

    async fn write_delta_chunk_to_staging(
        path: &Path,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), TransportError> {
        let mut file = crate::fs::File::options()
            .read(true)
            .write(true)
            .open(path)
            .await?;
        file.seek(SeekFrom::Start(offset)).await?;
        file.write_all(bytes).await?;
        file.flush().await?;
        Ok(())
    }

    async fn prepare_delta_receive_staging(
        dest_dir: &Path,
        manifest: &TransferManifest,
        target_wire: &DeltaManifestWire,
        state: &ReceiverDeltaState,
        staging_paths: &[PathBuf],
    ) -> Result<BTreeSet<DeltaChunkKey>, TransportError> {
        let Some(baseline) = state.baseline.as_ref() else {
            return Err(TransportError::Frame(
                "delta receive selected without verified receiver baseline".to_string(),
            ));
        };
        let pending: BTreeSet<DeltaChunkKey> = state
            .request
            .missing_chunks
            .iter()
            .map(delta_chunk_key)
            .collect();
        if pending.len() != state.request.missing_chunks.len() {
            return Err(TransportError::Frame(
                "delta ObjectRequest contains duplicate missing chunks".to_string(),
            ));
        }

        for (entry, staging_path) in manifest.entries.iter().zip(staging_paths) {
            if let Some(parent) = staging_path.parent() {
                crate::fs::create_dir_all(parent).await?;
            }
            let file = crate::fs::File::create(staging_path).await?;
            file.set_len(entry.size).await?;
        }

        for chunk in &target_wire.chunks {
            if pending.contains(&delta_chunk_key(chunk)) {
                continue;
            }
            let key = delta_content_key(chunk.content_id_hex.clone(), chunk.size_bytes);
            let bytes = baseline.chunks_by_content.get(&key).ok_or_else(|| {
                TransportError::Frame(format!(
                    "delta baseline cannot satisfy target chunk {}",
                    chunk.index
                ))
            })?;
            let staging_path = staging_paths
                .get(chunk.entry_index as usize)
                .ok_or_else(|| {
                    TransportError::Frame("delta chunk entry index out of range".to_string())
                })?;
            write_delta_chunk_to_staging(staging_path, chunk.entry_offset, bytes).await?;
        }

        Ok(pending)
    }

    async fn receive_delta_data_frame(
        frame: &Frame,
        manifest: &TransferManifest,
        staging_paths: &[PathBuf],
        pending: &mut BTreeSet<DeltaChunkKey>,
        received: &mut u64,
        config: &TransferConfig,
    ) -> Result<(), TransportError> {
        let (index, offset, chunk) = parse_data_frame(frame)?;
        let idx = index as usize;
        let entry = manifest.entries.get(idx).ok_or_else(|| {
            TransportError::Frame(format!("ObjectData for unknown entry index {index}"))
        })?;
        let size_bytes = u64::try_from(chunk.len())
            .map_err(|_| TransportError::Frame("delta ObjectData chunk too large".to_string()))?;
        if offset.saturating_add(size_bytes) > entry.size {
            return Err(TransportError::Frame(format!(
                "delta ObjectData entry {index} overruns declared size {}",
                entry.size
            )));
        }
        let content_id_hex = ContentId::from_bytes(chunk).to_hex();
        let key = DeltaChunkKey {
            entry_index: index,
            entry_offset: offset,
            size_bytes,
            content_id_hex,
        };
        if !pending.remove(&key) {
            return Err(TransportError::Frame(format!(
                "unexpected or duplicate delta ObjectData for entry {index} at offset {offset}"
            )));
        }
        *received = received.saturating_add(size_bytes);
        if *received > config.max_transfer_bytes {
            return Err(TransportError::TooLarge {
                size: *received,
                max: config.max_transfer_bytes,
            });
        }
        let staging_path = staging_paths.get(idx).ok_or_else(|| {
            TransportError::Frame("delta staging entry index out of range".to_string())
        })?;
        write_delta_chunk_to_staging(staging_path, offset, chunk).await
    }

    async fn finalize_delta_staging(
        manifest: &TransferManifest,
        staging_paths: &[PathBuf],
        read_buf: &mut [u8],
    ) -> Result<(Vec<EntryDigest>, bool), TransportError> {
        let mut digests = Vec::with_capacity(manifest.entries.len());
        let mut sha_ok = true;
        for (entry, staging_path) in manifest.entries.iter().zip(staging_paths) {
            let (size, content_id, content_sha256) =
                hash_file_streaming(staging_path, read_buf).await?;
            if size != entry.size || hex_encode(&content_sha256) != entry.sha256_hex {
                sha_ok = false;
            }
            digests.push(EntryDigest {
                rel_path: entry.rel_path.clone(),
                size,
                content_id,
                content_sha256,
            });
        }
        Ok((digests, sha_ok))
    }
}

#[cfg(test)]
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

/// Build a deterministic flat object graph over `(rel_path, bytes)` entries and
/// return `(graph, merkle_root_hex)`. The graph is a single directory root whose
/// edges are keyed by full relative path, so the merkle root commits to every
/// file's content and path. Identical builder on both sides ⇒ identical root.
///
/// Test-only: the streaming transport computes the same root via
/// [`flat_merkle_root_from_digests`]; this owned-graph builder is retained as a
/// differential oracle proving the two paths agree.
#[cfg(test)]
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

/// Stream a file off disk and emit it as `ObjectData` frames, reusing `buf` as
/// the only data-sized allocation. Peak memory is `buf.len()`, independent of
/// the file size.
async fn send_file_streaming<S>(
    cx: &Cx,
    transport: &mut FrameTransport<S>,
    index: u32,
    path: &Path,
    config: &TransferConfig,
    buf: &mut [u8],
) -> Result<(), TransportError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut file = crate::fs::File::open(path)
        .await
        .map_err(|e| TransportError::Source(format!("{}: {e}", path.display())))?;
    let mut offset: u64 = 0;
    loop {
        let n = file
            .read(buf)
            .await
            .map_err(|e| TransportError::Source(format!("{}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        let frame = data_frame(index, offset, &buf[..n])?;
        with_transport_timeout(
            cx,
            config.idle_timeout,
            "send data frame",
            transport.send(&frame),
        )
        .await?;
        offset = offset.saturating_add(n as u64);
    }
    Ok(())
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
    // The transfer_id is an off-wire string that is interpolated directly into
    // the on-disk staging-directory path (`.atp-staging-{transfer_id}-{seq}`).
    // A legitimate sender always emits a 32-char lowercase hex token
    // (`transfer_id_hex`), so constrain it to a bounded alphanumeric token here.
    // Without this, a hostile peer could set `transfer_id` to e.g.
    // `x/../../../../tmp/pwn` and steer `remove_dir_all` / file writes outside
    // the destination directory (directory traversal). Every other off-wire path
    // field (`root_name`, per-entry `rel_path`) is already sanitized; this closes
    // the last gap.
    if manifest.transfer_id.is_empty()
        || manifest.transfer_id.len() > 64
        || !manifest
            .transfer_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric())
    {
        return Err(TransportError::Frame(format!(
            "unsafe manifest transfer_id: {}",
            manifest.transfer_id
        )));
    }
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

/// Reject a manifest where any entry path is nested under another entry declared
/// as a symlink. `join_relative` only blocks lexical `..`, so committing a
/// symlink and then writing a nested entry would traverse the freshly-created
/// link and escape `dest_dir` (a symlink-slip / tar-slip class escape). Checked
/// up front, before any filesystem mutation, so the transfer fails closed.
fn reject_symlink_traversal(manifest: &TransferManifest) -> Result<(), TransportError> {
    let symlink_paths: Vec<&str> = manifest
        .entries
        .iter()
        .filter(|e| {
            e.metadata
                .as_ref()
                .is_some_and(|m| matches!(m.file_kind, FileKind::Symlink))
        })
        .map(|e| e.rel_path.as_str())
        .collect();
    if symlink_paths.is_empty() {
        return Ok(());
    }
    for entry in &manifest.entries {
        let p = entry.rel_path.as_str();
        for sym in &symlink_paths {
            // `p` is nested under symlink `sym` iff `sym` is a strict,
            // component-aligned prefix of `p` (so `p` would be written through
            // the link). The symlink entry itself (`p == sym`) is fine.
            if p.len() > sym.len() && p.as_bytes()[sym.len()] == b'/' && p.starts_with(sym) {
                return Err(TransportError::Source(format!(
                    "manifest entry {p} is nested under symlink entry {sym}; refusing to \
                     write through a link (would escape the destination)"
                )));
            }
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

/// Write `chunk` to `file`, punching holes for long zero runs by seeking past
/// them instead of writing, so a sparse source stays sparse on disk. The caller
/// must have `set_len` the file to its full length up front, so any trailing
/// hole is preserved. Content is unchanged — holes read back as zeros — so the
/// per-entry digest (computed over the full received stream) is unaffected.
async fn write_chunk_sparse(
    file: &mut crate::fs::File,
    chunk: &[u8],
) -> Result<(), TransportError> {
    // Zero runs at least this long (one filesystem block) are punched as holes;
    // shorter runs are written, since a sub-block hole saves no allocation.
    const HOLE_THRESHOLD: usize = 4096;
    let mut pos = 0;
    while pos < chunk.len() {
        let start = pos;
        if chunk[pos] == 0 {
            while pos < chunk.len() && chunk[pos] == 0 {
                pos += 1;
            }
            let run = pos - start;
            if run >= HOLE_THRESHOLD {
                let run = i64::try_from(run).map_err(|_| {
                    TransportError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "sparse zero run length exceeds i64::MAX",
                    ))
                })?;
                file.seek(std::io::SeekFrom::Current(run)).await?;
            } else {
                file.write_all(&chunk[start..pos]).await?;
            }
        } else {
            while pos < chunk.len() && chunk[pos] != 0 {
                pos += 1;
            }
            file.write_all(&chunk[start..pos]).await?;
        }
    }
    Ok(())
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DeltaChunkKey {
    entry_index: u32,
    entry_offset: u64,
    size_bytes: u64,
    content_id_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DeltaContentKey {
    content_id_hex: String,
    size_bytes: u64,
}

#[derive(Debug)]
struct ReceiverDeltaBaseline {
    manifest: PersistentChunkManifest,
    store: DeltaPlannerStore,
    chunks_by_content: BTreeMap<DeltaContentKey, Vec<u8>>,
}

#[derive(Debug)]
struct ReceiverDeltaState {
    request: DeltaObjectRequest,
    baseline: Option<ReceiverDeltaBaseline>,
}

fn delta_chunk_key(chunk: &DeltaChunkWire) -> DeltaChunkKey {
    DeltaChunkKey {
        entry_index: chunk.entry_index,
        entry_offset: chunk.entry_offset,
        size_bytes: chunk.size_bytes,
        content_id_hex: chunk.content_id_hex.clone(),
    }
}

fn delta_content_key(content_id_hex: impl Into<String>, size_bytes: u64) -> DeltaContentKey {
    DeltaContentKey {
        content_id_hex: content_id_hex.into(),
        size_bytes,
    }
}

fn decode_hex_32(hex_value: &str, label: &str) -> Result<[u8; 32], TransportError> {
    if hex_value.len() != 64 {
        return Err(TransportError::Frame(format!(
            "{label} must be exactly 64 hex characters"
        )));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_value, &mut out)
        .map_err(|err| TransportError::Frame(format!("decode {label}: {err}")))?;
    Ok(out)
}

fn planner_manifest_from_wire(
    manifest: &DeltaManifestWire,
) -> Result<PersistentChunkManifest, TransportError> {
    if manifest.schema != DELTA_CHUNK_SCHEMA {
        return Err(TransportError::Frame(format!(
            "unsupported delta manifest schema: {}",
            manifest.schema
        )));
    }
    let chunks = manifest
        .chunks
        .iter()
        .map(|chunk| {
            Ok(CasChunkRef {
                index: chunk.index,
                byte_offset: chunk.stream_offset,
                size_bytes: chunk.size_bytes,
                content_id: ContentId::new(decode_hex_32(
                    &chunk.content_id_hex,
                    "delta content id",
                )?),
            })
        })
        .collect::<Result<Vec<_>, TransportError>>()?;
    let planned =
        PersistentChunkManifest::new(manifest.tree_id.clone(), chunks).map_err(|err| {
            TransportError::Frame(format!("invalid delta manifest in ObjectManifest: {err}"))
        })?;
    if planned.total_size_bytes != manifest.total_size_bytes {
        return Err(TransportError::Frame(format!(
            "delta manifest total size mismatch: wire {}, computed {}",
            manifest.total_size_bytes, planned.total_size_bytes
        )));
    }
    if planned.merkle_root.to_hex() != manifest.merkle_root_hex {
        return Err(TransportError::Frame(format!(
            "delta manifest Merkle root mismatch: wire {}, computed {}",
            manifest.merkle_root_hex,
            planned.merkle_root.to_hex()
        )));
    }
    Ok(planned)
}

fn fallback_reason_label(reason: DeltaResyncFallbackReason) -> &'static str {
    match reason {
        DeltaResyncFallbackReason::NoReceiverManifest => "no_receiver_manifest",
        DeltaResyncFallbackReason::ReceiverCasCoverageIncomplete => {
            "receiver_cas_coverage_incomplete"
        }
        DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject => {
            "delta_not_smaller_than_full_object"
        }
    }
}

async fn build_delta_manifest_from_entries(
    tree_id: String,
    entries: &[SourceEntry],
    metadatas: &[EntryMetadata],
    chunk_size: usize,
) -> Result<DeltaManifestWire, TransportError> {
    let chunk_size = chunk_size.max(1);
    let mut wire_chunks = Vec::new();
    let mut planner_chunks = Vec::new();
    let mut stream_offset = 0u64;
    let mut index = 0u32;

    for (entry_index, (entry, metadata)) in entries.iter().zip(metadatas).enumerate() {
        if !matches!(metadata.file_kind, FileKind::Regular) || metadata.hardlink_target.is_some() {
            continue;
        }
        let entry_index = u32::try_from(entry_index)
            .map_err(|_| TransportError::Frame("too many delta manifest entries".to_string()))?;
        append_file_delta_chunks(
            &entry.abs_path,
            &entry.rel_path,
            entry_index,
            chunk_size,
            &mut index,
            &mut stream_offset,
            &mut wire_chunks,
            &mut planner_chunks,
        )
        .await?;
    }

    let planner = PersistentChunkManifest::new(tree_id.clone(), planner_chunks)
        .map_err(|err| TransportError::Frame(format!("build sender delta manifest: {err}")))?;
    Ok(DeltaManifestWire {
        schema: DELTA_CHUNK_SCHEMA.to_string(),
        tree_id,
        chunk_size,
        total_size_bytes: planner.total_size_bytes,
        merkle_root_hex: planner.merkle_root.to_hex(),
        chunks: wire_chunks,
    })
}

async fn append_file_delta_chunks(
    path: &Path,
    rel_path: &str,
    entry_index: u32,
    chunk_size: usize,
    next_index: &mut u32,
    stream_offset: &mut u64,
    wire_chunks: &mut Vec<DeltaChunkWire>,
    planner_chunks: &mut Vec<CasChunkRef>,
) -> Result<(), TransportError> {
    let mut file = crate::fs::File::open(path)
        .await
        .map_err(|err| TransportError::Source(format!("{}: {err}", path.display())))?;
    let mut entry_offset = 0u64;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|err| TransportError::Source(format!("{}: {err}", path.display())))?;
        if n == 0 {
            break;
        }
        let bytes = &buf[..n];
        let size_bytes = u64::try_from(n)
            .map_err(|_| TransportError::Frame("delta chunk length overflow".to_string()))?;
        let content_id = ContentId::from_bytes(bytes);
        let chunk = CasChunkRef {
            index: *next_index,
            byte_offset: *stream_offset,
            size_bytes,
            content_id: content_id.clone(),
        };
        planner_chunks.push(chunk);
        wire_chunks.push(DeltaChunkWire {
            index: *next_index,
            entry_index,
            rel_path: rel_path.to_string(),
            entry_offset,
            stream_offset: *stream_offset,
            size_bytes,
            content_id_hex: content_id.to_hex(),
        });
        *next_index = (*next_index)
            .checked_add(1)
            .ok_or_else(|| TransportError::Frame("delta chunk index overflow".to_string()))?;
        entry_offset = entry_offset
            .checked_add(size_bytes)
            .ok_or_else(|| TransportError::Frame("delta entry offset overflow".to_string()))?;
        *stream_offset = (*stream_offset)
            .checked_add(size_bytes)
            .ok_or_else(|| TransportError::Frame("delta stream offset overflow".to_string()))?;
    }
    Ok(())
}

async fn send_full_entries_streaming<S>(
    cx: &Cx,
    transport: &mut FrameTransport<S>,
    entries: &[SourceEntry],
    metadatas: &[EntryMetadata],
    digests: &[EntryDigest],
    config: &TransferConfig,
    read_buf: &mut [u8],
    mut on_progress: impl FnMut(u64, u64),
) -> Result<u64, TransportError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let total_bytes = digests
        .iter()
        .fold(0u64, |sum, digest| sum.saturating_add(digest.size));
    let mut sent_bytes = 0u64;
    for (i, entry) in entries.iter().enumerate() {
        cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
        if !matches!(metadatas[i].file_kind, FileKind::Regular)
            || metadatas[i].hardlink_target.is_some()
        {
            continue;
        }
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        send_file_streaming(cx, transport, index, &entry.abs_path, config, read_buf).await?;
        sent_bytes = sent_bytes.saturating_add(digests[i].size);
        on_progress(sent_bytes, total_bytes);
    }
    on_progress(total_bytes, total_bytes);
    Ok(total_bytes)
}

async fn send_delta_entries_streaming<S>(
    cx: &Cx,
    transport: &mut FrameTransport<S>,
    entries: &[SourceEntry],
    manifest: &DeltaManifestWire,
    request: &DeltaObjectRequest,
    config: &TransferConfig,
    mut on_progress: impl FnMut(u64, u64),
) -> Result<u64, TransportError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let advertised: BTreeSet<DeltaChunkKey> = manifest.chunks.iter().map(delta_chunk_key).collect();
    let requested: BTreeSet<DeltaChunkKey> =
        request.missing_chunks.iter().map(delta_chunk_key).collect();
    if requested.len() != request.missing_chunks.len() {
        return Err(TransportError::Frame(
            "delta ObjectRequest contains duplicate missing chunks".to_string(),
        ));
    }
    if !requested.is_subset(&advertised) {
        return Err(TransportError::Frame(
            "delta ObjectRequest asks for a chunk outside the sender manifest".to_string(),
        ));
    }

    let total_bytes = request.missing_bytes;
    let mut sent_bytes = 0u64;
    for chunk in &request.missing_chunks {
        cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
        let entry = entries
            .get(chunk.entry_index as usize)
            .ok_or_else(|| TransportError::Frame("delta chunk entry index out of range".into()))?;
        let mut file = crate::fs::File::open(&entry.abs_path)
            .await
            .map_err(|err| {
                TransportError::Source(format!("{}: {err}", entry.abs_path.display()))
            })?;
        file.seek(SeekFrom::Start(chunk.entry_offset)).await?;
        let len = usize::try_from(chunk.size_bytes).map_err(|_| {
            TransportError::Frame("delta requested chunk size exceeds usize::MAX".to_string())
        })?;
        let mut bytes = vec![0u8; len];
        file.read_exact(&mut bytes).await.map_err(|err| {
            TransportError::Source(format!("{}: {err}", entry.abs_path.display()))
        })?;
        let observed = ContentId::from_bytes(&bytes).to_hex();
        if observed != chunk.content_id_hex {
            return Err(TransportError::Integrity(format!(
                "delta source chunk hash drift for {} at offset {}",
                chunk.rel_path, chunk.entry_offset
            )));
        }
        let frame = data_frame(chunk.entry_index, chunk.entry_offset, &bytes)?;
        with_transport_timeout(
            cx,
            config.idle_timeout,
            "send delta data frame",
            transport.send(&frame),
        )
        .await?;
        sent_bytes = sent_bytes.saturating_add(chunk.size_bytes);
        on_progress(sent_bytes, total_bytes);
    }
    on_progress(total_bytes, total_bytes);
    Ok(total_bytes)
}

async fn build_receiver_delta_state(
    dest_dir: &Path,
    manifest: &TransferManifest,
    config: &TransferConfig,
) -> Result<ReceiverDeltaState, TransportError> {
    let Some(delta_manifest) = manifest.delta_manifest.as_ref() else {
        return Ok(ReceiverDeltaState {
            request: DeltaObjectRequest::full("", None, "sender_delta_manifest_unavailable"),
            baseline: None,
        });
    };
    let sender_manifest = planner_manifest_from_wire(delta_manifest)?;
    if !config.enable_delta {
        return Ok(ReceiverDeltaState {
            request: DeltaObjectRequest::full(
                sender_manifest.merkle_root.to_hex(),
                None,
                "receiver_delta_disabled",
            ),
            baseline: None,
        });
    }
    if manifest.entries.iter().any(delta_unsupported_metadata) {
        return Ok(ReceiverDeltaState {
            request: DeltaObjectRequest::full(
                sender_manifest.merkle_root.to_hex(),
                None,
                "delta_unsupported_metadata",
            ),
            baseline: None,
        });
    }

    let Some(baseline) =
        build_receiver_delta_baseline(dest_dir, manifest, delta_manifest, config).await?
    else {
        return Ok(ReceiverDeltaState {
            request: DeltaObjectRequest::full(
                sender_manifest.merkle_root.to_hex(),
                None,
                fallback_reason_label(DeltaResyncFallbackReason::NoReceiverManifest),
            ),
            baseline: None,
        });
    };

    let plan = plan_incremental_resync(&sender_manifest, Some(&baseline.manifest), &baseline.store);
    let receiver_merkle_root_hex = Some(baseline.manifest.merkle_root.to_hex());
    let request = match plan.mode {
        DeltaResyncMode::AlreadyInSync => DeltaObjectRequest {
            mode: DeltaWireMode::AlreadyInSync,
            fallback_reason: None,
            sender_merkle_root_hex: plan.sender_merkle_root.to_hex(),
            receiver_merkle_root_hex,
            missing_bytes: 0,
            shared_chunks: plan.shared_chunks,
            stale_chunks: 0,
            missing_chunks: Vec::new(),
        },
        DeltaResyncMode::FullObjectFallback => DeltaObjectRequest {
            mode: DeltaWireMode::FullObject,
            fallback_reason: Some(
                fallback_reason_label(
                    plan.fallback_reason
                        .unwrap_or(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject),
                )
                .to_string(),
            ),
            sender_merkle_root_hex: plan.sender_merkle_root.to_hex(),
            receiver_merkle_root_hex,
            missing_bytes: plan.missing_bytes,
            shared_chunks: plan.shared_chunks,
            stale_chunks: plan.stale_chunks.len() as u64,
            missing_chunks: Vec::new(),
        },
        DeltaResyncMode::DeltaChunks => DeltaObjectRequest {
            mode: DeltaWireMode::DeltaChunks,
            fallback_reason: None,
            sender_merkle_root_hex: plan.sender_merkle_root.to_hex(),
            receiver_merkle_root_hex,
            missing_bytes: plan.missing_bytes,
            shared_chunks: plan.shared_chunks,
            stale_chunks: plan.stale_chunks.len() as u64,
            missing_chunks: wire_missing_chunks(delta_manifest, &plan.missing_chunks)?,
        },
    };

    Ok(ReceiverDeltaState {
        baseline: matches!(
            request.mode,
            DeltaWireMode::DeltaChunks | DeltaWireMode::AlreadyInSync
        )
        .then_some(baseline),
        request,
    })
}

fn delta_unsupported_metadata(entry: &ManifestEntry) -> bool {
    entry.metadata.as_ref().is_some_and(|metadata| {
        !matches!(metadata.file_kind, FileKind::Regular) || metadata.hardlink_target.is_some()
    })
}

fn wire_missing_chunks(
    manifest: &DeltaManifestWire,
    missing_chunks: &[CasChunkRef],
) -> Result<Vec<DeltaChunkWire>, TransportError> {
    let mut by_ref = BTreeMap::new();
    for chunk in &manifest.chunks {
        by_ref.insert(
            (
                chunk.index,
                chunk.stream_offset,
                chunk.size_bytes,
                chunk.content_id_hex.clone(),
            ),
            chunk,
        );
    }
    missing_chunks
        .iter()
        .map(|chunk| {
            let key = (
                chunk.index,
                chunk.byte_offset,
                chunk.size_bytes,
                chunk.content_id.to_hex(),
            );
            by_ref.get(&key).copied().cloned().ok_or_else(|| {
                TransportError::Frame(
                    "delta planner selected a chunk absent from wire manifest".into(),
                )
            })
        })
        .collect()
}

async fn build_receiver_delta_baseline(
    dest_dir: &Path,
    manifest: &TransferManifest,
    delta_manifest: &DeltaManifestWire,
    config: &TransferConfig,
) -> Result<Option<ReceiverDeltaBaseline>, TransportError> {
    let base = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
    if !base.exists() {
        return Ok(None);
    }
    let (_, _, entries) = collect_entries(&base).await?;
    let mut store = DeltaPlannerStore::new();
    let mut chunks_by_content = BTreeMap::new();
    let mut planner_chunks = Vec::new();
    let mut digests = Vec::with_capacity(entries.len());
    let mut read_buf = vec![0u8; config.chunk_size.max(1)];
    let mut stream_offset = 0u64;
    let mut index = 0u32;

    for entry in entries {
        let metadata = read_entry_metadata(&entry.abs_path, &config.metadata_policy).await?;
        if !matches!(metadata.file_kind, FileKind::Regular) || metadata.hardlink_target.is_some() {
            return Ok(None);
        }
        let (size, content_id, content_sha256) =
            hash_file_streaming(&entry.abs_path, &mut read_buf).await?;
        digests.push(EntryDigest {
            rel_path: entry.rel_path.clone(),
            size,
            content_id,
            content_sha256,
        });
        append_receiver_delta_chunks(
            &entry.abs_path,
            delta_manifest.chunk_size.max(1),
            &mut index,
            &mut stream_offset,
            &mut store,
            &mut chunks_by_content,
            &mut planner_chunks,
        )
        .await?;
    }

    let receiver_tree_id = flat_merkle_root_from_digests(&digests);
    let receiver_manifest = PersistentChunkManifest::new(receiver_tree_id, planner_chunks)
        .map_err(|err| TransportError::Frame(format!("build receiver delta manifest: {err}")))?;
    Ok(Some(ReceiverDeltaBaseline {
        manifest: receiver_manifest,
        store,
        chunks_by_content,
    }))
}

async fn append_receiver_delta_chunks(
    path: &Path,
    chunk_size: usize,
    next_index: &mut u32,
    stream_offset: &mut u64,
    store: &mut DeltaPlannerStore,
    chunks_by_content: &mut BTreeMap<DeltaContentKey, Vec<u8>>,
    planner_chunks: &mut Vec<CasChunkRef>,
) -> Result<(), TransportError> {
    let mut file = crate::fs::File::open(path)
        .await
        .map_err(|err| TransportError::Source(format!("{}: {err}", path.display())))?;
    let mut buf = vec![0u8; chunk_size.max(1)];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|err| TransportError::Source(format!("{}: {err}", path.display())))?;
        if n == 0 {
            break;
        }
        let bytes = &buf[..n];
        let insert = store
            .insert(bytes)
            .map_err(|err| TransportError::Frame(format!("receiver delta CAS insert: {err}")))?;
        let size_bytes = u64::try_from(n)
            .map_err(|_| TransportError::Frame("delta chunk length overflow".to_string()))?;
        let content_id_hex = insert.content_id.to_hex();
        chunks_by_content
            .entry(delta_content_key(content_id_hex.clone(), size_bytes))
            .or_insert_with(|| bytes.to_vec());
        planner_chunks.push(CasChunkRef {
            index: *next_index,
            byte_offset: *stream_offset,
            size_bytes,
            content_id: insert.content_id,
        });
        *next_index = (*next_index)
            .checked_add(1)
            .ok_or_else(|| TransportError::Frame("delta chunk index overflow".to_string()))?;
        *stream_offset = (*stream_offset)
            .checked_add(size_bytes)
            .ok_or_else(|| TransportError::Frame("delta stream offset overflow".to_string()))?;
    }
    Ok(())
}

async fn send_receipt_and_close<S>(
    cx: &Cx,
    transport: &mut FrameTransport<S>,
    config: &TransferConfig,
    receipt: &ReceiveReceipt,
) -> Result<(), TransportError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let proof = json_frame(FrameType::Proof, receipt)?;
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
    Ok(())
}

async fn commit_verified_staging(
    cx: &Cx,
    dest_dir: &Path,
    manifest: &TransferManifest,
    config: &TransferConfig,
    staging_paths: &[PathBuf],
) -> Result<Vec<PathBuf>, TransportError> {
    let mut committed_paths = Vec::new();
    let base = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
    for (entry, staging_path) in manifest.entries.iter().zip(staging_paths.iter()) {
        let out_path = if manifest.is_directory {
            join_relative(&base, &entry.rel_path)?
        } else {
            base.clone()
        };

        if let Some(meta) = &entry.metadata {
            if meta.file_kind.is_special() {
                if matches!(meta.file_kind, FileKind::Fifo) && config.allow_special_files {
                    if let Some(parent) = out_path.parent() {
                        crate::fs::create_dir_all(parent).await?;
                    }
                    let mode = meta.unix_mode.unwrap_or(0o644);
                    let _ = crate::fs::remove_file(&out_path).await;
                    crate::net::atp::transport_common::metadata::recreate_fifo(&out_path, mode)
                        .await?;
                    apply_entry_metadata_best_effort(cx, &out_path, meta).await;
                    committed_paths.push(out_path);
                    continue;
                }
                if cx.trace_buffer().is_some() {
                    let path_str = out_path.display().to_string();
                    let kind = format!("{:?}", meta.file_kind);
                    cx.trace_with_fields(
                        "atp_tcp_special_file_skipped",
                        &[("path", path_str.as_str()), ("kind", kind.as_str())],
                    );
                }
                continue;
            }
        }

        if let Some(parent) = out_path.parent() {
            crate::fs::create_dir_all(parent).await?;
        }

        if let Some(meta) = &entry.metadata {
            if matches!(meta.file_kind, FileKind::Directory) {
                crate::fs::create_dir_all(&out_path).await?;
                apply_entry_metadata_best_effort(cx, &out_path, meta).await;
                committed_paths.push(out_path);
                continue;
            }
        }

        let symlink_target = entry.metadata.as_ref().and_then(|m| {
            matches!(m.file_kind, FileKind::Symlink)
                .then(|| m.symlink_target.clone())
                .flatten()
        });
        if let Some(target) = symlink_target {
            let _ = crate::fs::remove_file(&out_path).await;
            crate::fs::symlink(&target, &out_path).await?;
            committed_paths.push(out_path);
            continue;
        }

        let hardlink_target = entry
            .metadata
            .as_ref()
            .and_then(|m| m.hardlink_target.clone());
        if let Some(primary_rel) = hardlink_target {
            let primary_path = join_relative(&base, &primary_rel)?;
            let _ = crate::fs::remove_file(&out_path).await;
            crate::fs::hard_link(&primary_path, &out_path).await?;
            committed_paths.push(out_path);
            continue;
        }

        crate::fs::rename(staging_path, &out_path).await?;
        if let Some(meta) = &entry.metadata {
            apply_entry_metadata_best_effort(cx, &out_path, meta).await;
        }
        committed_paths.push(out_path);
    }
    Ok(committed_paths)
}

#[cfg(any())]
mod unused_delta_payload_helpers {
    use super::*;

    async fn expect_object_complete<S>(
        cx: &Cx,
        transport: &mut FrameTransport<S>,
        config: &TransferConfig,
    ) -> Result<(), TransportError>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let frame = with_transport_timeout(
            cx,
            config.idle_timeout,
            "receive completion",
            transport.recv(),
        )
        .await?;
        match frame.frame_type() {
            FrameType::ObjectComplete | FrameType::Close => Ok(()),
            FrameType::Error => Err(TransportError::Frame(format!(
                "peer sent Error frame: {}",
                String::from_utf8_lossy(frame.payload())
            ))),
            other => Err(TransportError::Unexpected {
                got: other,
                expected: "ObjectComplete | Close",
            }),
        }
    }

    fn committed_paths_for_existing_manifest(
        dest_dir: &Path,
        manifest: &TransferManifest,
    ) -> Result<Vec<PathBuf>, TransportError> {
        let base = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
        manifest
            .entries
            .iter()
            .map(|entry| {
                if manifest.is_directory {
                    join_relative(&base, &entry.rel_path)
                } else {
                    Ok(base.clone())
                }
            })
            .collect()
    }

    async fn create_delta_staging_files(
        dest_dir: &Path,
        staging_dir: &Path,
        manifest: &TransferManifest,
        baseline: &ReceiverDeltaBaseline,
    ) -> Result<Vec<PathBuf>, TransportError> {
        let base = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
        let mut staging_paths = Vec::with_capacity(manifest.entries.len());
        let mut baseline_by_content = baseline.chunks_by_content.clone();

        for (index, entry) in manifest.entries.iter().enumerate() {
            let staging_path = staging_dir.join(index.to_string());
            let mut staged = crate::fs::File::create(&staging_path).await?;
            let mut written = 0u64;

            let Some(delta_manifest) = manifest.delta_manifest.as_ref() else {
                return Err(TransportError::Frame(
                    "delta staging requires sender delta manifest".to_string(),
                ));
            };
            for chunk in delta_manifest
                .chunks
                .iter()
                .filter(|chunk| chunk.entry_index as usize == index)
            {
                let key = delta_content_key(chunk.content_id_hex.clone(), chunk.size_bytes);
                if let Some(bytes) = baseline_by_content.get_mut(&key) {
                    staged.seek(SeekFrom::Start(chunk.entry_offset)).await?;
                    staged.write_all(bytes).await?;
                    written = written.saturating_add(chunk.size_bytes);
                }
            }

            staged.set_len(entry.size).await?;
            staged.flush().await?;
            let _ = written;
            staging_paths.push(staging_path);
        }

        let _ = base;
        Ok(staging_paths)
    }

    async fn receive_delta_payload<S>(
        cx: &Cx,
        transport: &mut FrameTransport<S>,
        config: &TransferConfig,
        manifest: &TransferManifest,
        staging_paths: &[PathBuf],
    ) -> Result<u64, TransportError>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let mut received = 0u64;
        loop {
            cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
            let frame = with_transport_timeout(
                cx,
                config.idle_timeout,
                "receive delta frame",
                transport.recv(),
            )
            .await?;
            match frame.frame_type() {
                FrameType::ObjectData => {
                    let (index, offset, chunk) = parse_data_frame(&frame)?;
                    let idx = index as usize;
                    let entry = manifest.entries.get(idx).ok_or_else(|| {
                        TransportError::Frame(format!("ObjectData for unknown entry index {index}"))
                    })?;
                    if offset.saturating_add(chunk.len() as u64) > entry.size {
                        return Err(TransportError::Frame(format!(
                            "delta ObjectData entry {index} overruns declared size {}",
                            entry.size
                        )));
                    }
                    let staging_path = staging_paths.get(idx).ok_or_else(|| {
                        TransportError::Frame(format!(
                            "missing delta staging path for entry {index}"
                        ))
                    })?;
                    let mut file = crate::fs::File::options()
                        .write(true)
                        .open(staging_path)
                        .await?;
                    file.seek(SeekFrom::Start(offset)).await?;
                    if config.sparse_files {
                        write_chunk_sparse(&mut file, chunk).await?;
                    } else {
                        file.write_all(chunk).await?;
                    }
                    file.flush().await?;
                    received = received.saturating_add(chunk.len() as u64);
                    if received > config.max_transfer_bytes {
                        return Err(TransportError::TooLarge {
                            size: received,
                            max: config.max_transfer_bytes,
                        });
                    }
                }
                FrameType::ObjectComplete | FrameType::Close => break,
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
        Ok(received)
    }

    async fn verify_staging_digests(
        manifest: &TransferManifest,
        staging_paths: &[PathBuf],
        chunk_size: usize,
    ) -> Result<(bool, bool, Vec<EntryDigest>), TransportError> {
        let mut read_buf = vec![0u8; chunk_size.max(1)];
        let mut sha_ok = true;
        let mut digests = Vec::with_capacity(manifest.entries.len());
        for (entry, path) in manifest.entries.iter().zip(staging_paths.iter()) {
            let (size, content_id, content_sha256) =
                hash_file_streaming(path, &mut read_buf).await?;
            if size != entry.size || hex_encode(&content_sha256) != entry.sha256_hex {
                sha_ok = false;
            }
            digests.push(EntryDigest {
                rel_path: entry.rel_path.clone(),
                size,
                content_id,
                content_sha256,
            });
        }
        let merkle_ok = flat_merkle_root_from_digests(&digests) == manifest.merkle_root_hex;
        Ok((sha_ok, merkle_ok, digests))
    }
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

fn trace_tcp_metadata_skips(cx: &Cx, out_path: &Path, skipped: &[(&'static str, String)]) {
    if cx.trace_buffer().is_none() || skipped.is_empty() {
        return;
    }
    let path_str = out_path.display().to_string();
    for (field, reason) in skipped {
        cx.trace_with_fields(
            "atp_tcp_metadata_skipped",
            &[
                ("path", path_str.as_str()),
                ("field", *field),
                ("reason", reason.as_str()),
            ],
        );
    }
}

async fn apply_entry_metadata_best_effort(cx: &Cx, out_path: &Path, meta: &EntryMetadata) {
    match apply_entry_metadata(out_path, meta).await {
        Ok(report) => trace_tcp_metadata_skips(cx, out_path, &report.skipped),
        Err(err) => {
            let skipped = [("apply", err.to_string())];
            trace_tcp_metadata_skips(cx, out_path, &skipped);
        }
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
    send_path_filtered(
        cx,
        addr,
        source,
        config,
        peer_id,
        &FilterSet::new(),
        |_, _| {},
    )
    .await
}

/// Like [`send_path`], but applies an include/exclude [`FilterSet`] to the source
/// walk (rsync `--filter` / `--exclude` / `--include`) and reports byte progress.
///
/// Excluded files — and files beneath an excluded directory — are dropped before
/// any hashing or transfer, so the manifest and the bytes on the wire commit to
/// only the selected set. An empty filter behaves exactly like [`send_path`].
/// Rescuing a file under an excluded directory requires including its ancestor
/// directories first (rsync semantics; see [`FilterSet::is_path_included`]).
///
/// `on_progress(bytes_sent, total_bytes)` is invoked after each content entry is
/// streamed, then once more at completion with `bytes_sent == total_bytes`, so a
/// caller can render a monotonic progress bar / ETA (see
/// [`transport_common::TransferProgress`]). Pass `|_, _| {}` to ignore it.
///
/// [`transport_common::TransferProgress`]: crate::net::atp::transport_common::TransferProgress
pub async fn send_path_filtered(
    cx: &Cx,
    addr: SocketAddr,
    source: &Path,
    config: TransferConfig,
    peer_id: &str,
    filter: &FilterSet,
    mut on_progress: impl FnMut(u64, u64) + Send,
) -> Result<SendReport, TransportError> {
    cx.checkpoint().map_err(|_| TransportError::Cancelled)?;

    let (root_name, is_directory, mut entries) = collect_entries(source).await?;
    if !filter.is_empty() {
        entries.retain(|entry| filter.is_path_included(&entry.rel_path));
    }

    // First pass: stream each file off disk to compute its size, content id, and
    // SHA-256 incrementally. `read_buf` is the only data-sized allocation and is
    // reused across files, so peak memory is `chunk_size`, not the transfer size.
    let mut read_buf = vec![0u8; config.chunk_size.max(1)];
    let mut digests: Vec<EntryDigest> = Vec::with_capacity(entries.len());
    let mut metadatas: Vec<EntryMetadata> = Vec::with_capacity(entries.len());
    let mut total_bytes: u64 = 0;
    // Hardlink detection: the first entry (by sorted path) for a given inode is
    // the primary that carries the content; later entries sharing the inode are
    // hardlinks to it (sent content-free, `hard_link`ed on the receiver).
    let mut hardlink_primary: std::collections::HashMap<(u64, u64), String> =
        std::collections::HashMap::new();
    for entry in &entries {
        cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
        let mut metadata = read_entry_metadata(&entry.abs_path, &config.metadata_policy).await?;
        if config.preserve_hardlinks && matches!(metadata.file_kind, FileKind::Regular) {
            if let Some(key) =
                crate::net::atp::transport_common::metadata::inode_key_if_regular(&entry.abs_path)
                    .await?
            {
                if let Some(primary) = hardlink_primary.get(&key) {
                    metadata.hardlink_target = Some(primary.clone());
                } else {
                    hardlink_primary.insert(key, entry.rel_path.clone());
                }
            }
        }
        // Only regular files carry content bytes. Symlinks (target in
        // `metadata`), empty directories, special files (FIFO/socket/device),
        // and hardlinks-to-a-primary are zero-content — crucially this avoids
        // `hash_file_streaming` opening a FIFO, which would block the sender.
        let zero_content =
            !matches!(metadata.file_kind, FileKind::Regular) || metadata.hardlink_target.is_some();
        let (size, content_id, content_sha256) = if zero_content {
            // Emit the canonical empty-content digest so the receiver — which
            // sees zero ObjectData frames for this entry — reconstructs the same
            // digest.
            let empty_sha: [u8; 32] = Sha256::digest(b"").into();
            (
                0u64,
                ObjectId::content(ContentId::from_bytes(b"")),
                empty_sha,
            )
        } else {
            hash_file_streaming(&entry.abs_path, &mut read_buf).await?
        };
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > config.max_transfer_bytes {
            return Err(TransportError::TooLarge {
                size: total_bytes,
                max: config.max_transfer_bytes,
            });
        }
        digests.push(EntryDigest {
            rel_path: entry.rel_path.clone(),
            size,
            content_id,
            content_sha256,
        });
        metadatas.push(metadata);
    }

    let merkle_root_hex = flat_merkle_root_from_digests(&digests);
    let metadata_pairs: Vec<(&str, &EntryMetadata)> = digests
        .iter()
        .zip(&metadatas)
        .map(|(d, m)| (d.rel_path.as_str(), m))
        .collect();
    let metadata_root_hex = metadata_commitment(&metadata_pairs);
    let delta_manifest = if config.enable_delta {
        Some(
            build_delta_manifest_from_entries(
                merkle_root_hex.clone(),
                &entries,
                &metadatas,
                config.chunk_size,
            )
            .await?,
        )
    } else {
        None
    };
    let manifest_entries: Vec<ManifestEntry> = digests
        .iter()
        .zip(&metadatas)
        .enumerate()
        .map(|(i, (d, m))| ManifestEntry {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            rel_path: d.rel_path.clone(),
            size: d.size,
            sha256_hex: hex_encode(&d.content_sha256),
            metadata: if m.is_bare() { None } else { Some(m.clone()) },
        })
        .collect();
    let transfer_id = transfer_id_hex(&merkle_root_hex, total_bytes, manifest_entries.len());
    let manifest = TransferManifest {
        transfer_id: transfer_id.clone(),
        root_name,
        is_directory,
        total_bytes,
        merkle_root_hex: merkle_root_hex.clone(),
        metadata_root_hex,
        entries: manifest_entries,
        delta_manifest,
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
    let request_frame = with_transport_timeout(
        cx,
        config.idle_timeout,
        "receive object request",
        transport.recv(),
    )
    .await?;
    if request_frame.frame_type() != FrameType::ObjectRequest {
        return Err(TransportError::Unexpected {
            got: request_frame.frame_type(),
            expected: "ObjectRequest",
        });
    }
    let delta_request: DeltaObjectRequest = parse_json(&request_frame)?;

    // Bulk data, entry by entry — second streaming pass. For a delta request,
    // only receiver-missing chunks are re-read and framed. Otherwise this is the
    // legacy full-object stream, preserving the existing fallback path.
    let bytes_sent = match delta_request.mode {
        DeltaWireMode::AlreadyInSync => {
            on_progress(total_bytes, total_bytes);
            0
        }
        DeltaWireMode::DeltaChunks => {
            let delta_manifest = manifest.delta_manifest.as_ref().ok_or_else(|| {
                TransportError::Frame(
                    "receiver requested delta without sender manifest".to_string(),
                )
            })?;
            send_delta_entries_streaming(
                cx,
                &mut transport,
                &entries,
                delta_manifest,
                &delta_request,
                &config,
                &mut on_progress,
            )
            .await?
        }
        DeltaWireMode::FullObject => {
            send_full_entries_streaming(
                cx,
                &mut transport,
                &entries,
                &metadatas,
                &digests,
                &config,
                &mut read_buf,
                &mut on_progress,
            )
            .await?
        }
    };

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
        bytes_sent,
        files: u32::try_from(entries.len()).unwrap_or(u32::MAX),
        symbols_sent: 0,
        feedback_rounds: 0,
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

/// RAII backstop that reclaims a receive staging directory if the
/// `receive_connection` future is dropped before reaching one of its
/// cooperative cleanup paths — for example when [`serve`] aborts an in-flight
/// receive task on cancellation (`abort` drops the task future without polling
/// it to a `return`). The cooperative exits remove the directory asynchronously
/// and then [`StagingDirGuard::disarm`] this guard, so the synchronous reclaim
/// here only fires on a hard future-drop. That is a rare, bounded best-effort
/// cleanup (one `remove_dir_all` on a small per-transfer scratch dir), not a hot
/// path, so a blocking host-boundary call in `Drop` is acceptable here.
struct StagingDirGuard {
    dir: PathBuf,
    armed: bool,
}

impl StagingDirGuard {
    fn new(dir: PathBuf) -> Self {
        Self { dir, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingDirGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

async fn receive_delta_chunks_and_commit<S>(
    cx: &Cx,
    transport: &mut FrameTransport<S>,
    peer: SocketAddr,
    dest_dir: &Path,
    config: &TransferConfig,
    manifest: &TransferManifest,
    baseline: &ReceiverDeltaBaseline,
    request: &DeltaObjectRequest,
) -> Result<ReceiveReport, TransportError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let delta_manifest = manifest.delta_manifest.as_ref().ok_or_else(|| {
        TransportError::Frame("delta receive selected without sender manifest".to_string())
    })?;
    let requested_keys: BTreeSet<DeltaChunkKey> =
        request.missing_chunks.iter().map(delta_chunk_key).collect();
    let requested_by_key: BTreeMap<DeltaChunkKey, &DeltaChunkWire> = request
        .missing_chunks
        .iter()
        .map(|chunk| (delta_chunk_key(chunk), chunk))
        .collect();
    if requested_keys.len() != request.missing_chunks.len() {
        return Err(TransportError::Frame(
            "delta ObjectRequest contains duplicate missing chunks".to_string(),
        ));
    }

    let mut received_chunks = BTreeMap::<DeltaContentKey, Vec<u8>>::new();
    let mut received_keys = BTreeSet::<DeltaChunkKey>::new();
    let mut received = 0u64;
    let recv_result: Result<(), TransportError> = async {
        loop {
            cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
            let frame =
                with_transport_timeout(cx, config.idle_timeout, "receive frame", transport.recv())
                    .await?;
            match frame.frame_type() {
                FrameType::ObjectData => {
                    let (entry_index, entry_offset, chunk) = parse_data_frame(&frame)?;
                    let size_bytes = u64::try_from(chunk.len()).map_err(|_| {
                        TransportError::Frame("delta chunk length overflow".to_string())
                    })?;
                    let content_id_hex = ContentId::from_bytes(chunk).to_hex();
                    let key = DeltaChunkKey {
                        entry_index,
                        entry_offset,
                        size_bytes,
                        content_id_hex: content_id_hex.clone(),
                    };
                    if !requested_keys.contains(&key) {
                        return Err(TransportError::Frame(format!(
                            "unexpected delta chunk for entry {entry_index} offset {entry_offset}"
                        )));
                    }
                    if !received_keys.insert(key) {
                        return Err(TransportError::Frame(format!(
                            "duplicate delta chunk for entry {entry_index} offset {entry_offset}"
                        )));
                    }
                    received = received.saturating_add(size_bytes);
                    if received > config.max_transfer_bytes {
                        return Err(TransportError::TooLarge {
                            size: received,
                            max: config.max_transfer_bytes,
                        });
                    }
                    received_chunks
                        .entry(delta_content_key(content_id_hex, size_bytes))
                        .or_insert_with(|| chunk.to_vec());
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
        if received_keys != requested_keys {
            return Err(TransportError::Frame(
                "delta sender did not provide every requested chunk".to_string(),
            ));
        }
        Ok(())
    }
    .await;
    recv_result?;

    let staging_seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
    let staging_dir = dest_dir.join(format!(
        ".atp-staging-{}-{staging_seq}",
        manifest.transfer_id
    ));
    let _ = crate::fs::remove_dir_all(&staging_dir).await;
    crate::fs::create_dir_all(&staging_dir).await?;
    let mut staging_guard = StagingDirGuard::new(staging_dir.clone());

    let mut chunks_by_entry = BTreeMap::<u32, Vec<&DeltaChunkWire>>::new();
    for chunk in &delta_manifest.chunks {
        chunks_by_entry
            .entry(chunk.entry_index)
            .or_default()
            .push(chunk);
    }
    for chunks in chunks_by_entry.values_mut() {
        chunks.sort_by_key(|chunk| chunk.entry_offset);
    }

    let mut digests = Vec::with_capacity(manifest.entries.len());
    let mut staging_paths = Vec::with_capacity(manifest.entries.len());
    let reassemble_result: Result<(), TransportError> = async {
        for entry in &manifest.entries {
            let idx = entry.index;
            let staging_path = staging_dir.join(idx.to_string());
            let mut state = StagedEntryReceive::new(staging_path.clone());
            let mut active_file: Option<crate::fs::File> = None;
            let mut expected_offset = 0u64;
            if let Some(chunks) = chunks_by_entry.get(&idx) {
                let mut file = crate::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&staging_path)
                    .await?;
                state.mark_created();
                for chunk in chunks {
                    if chunk.entry_offset != expected_offset {
                        return Err(TransportError::Frame(format!(
                            "delta reassembly non-contiguous chunk for {}: expected {}, observed {}",
                            chunk.rel_path, expected_offset, chunk.entry_offset
                        )));
                    }
                    let content_key =
                        delta_content_key(chunk.content_id_hex.clone(), chunk.size_bytes);
                    let bytes = received_chunks
                        .get(&content_key)
                        .or_else(|| baseline.chunks_by_content.get(&content_key))
                        .ok_or_else(|| {
                            TransportError::Frame(format!(
                                "delta reassembly missing chunk for {} at offset {}",
                                chunk.rel_path, chunk.entry_offset
                            ))
                        })?;
                    if ContentId::from_bytes(bytes).to_hex() != chunk.content_id_hex {
                        return Err(TransportError::Integrity(format!(
                            "delta reassembly content id mismatch for {} at offset {}",
                            chunk.rel_path, chunk.entry_offset
                        )));
                    }
                    file.write_all(bytes).await?;
                    state.update_with_chunk(bytes);
                    expected_offset = expected_offset.checked_add(chunk.size_bytes).ok_or_else(|| {
                        TransportError::Frame("delta reassembly offset overflow".to_string())
                    })?;
                }
                active_file = Some(file);
            }
            if let Some(mut file) = active_file {
                file.flush().await?;
            }
            if expected_offset != entry.size {
                return Err(TransportError::Frame(format!(
                    "delta reassembly size mismatch for {}: expected {}, rebuilt {}",
                    entry.rel_path, entry.size, expected_offset
                )));
            }
            let (digest, staging_path, created) = state.finalize(entry.rel_path.clone());
            if !created {
                crate::fs::File::create(&staging_path).await?;
            }
            digests.push(digest);
            staging_paths.push(staging_path);
        }
        Ok(())
    }
    .await;

    if let Err(err) = reassemble_result {
        let _ = crate::fs::remove_dir_all(&staging_dir).await;
        return Err(err);
    }

    let sha_ok = digests
        .iter()
        .zip(&manifest.entries)
        .all(|(digest, entry)| {
            digest.size == entry.size && hex_encode(&digest.content_sha256) == entry.sha256_hex
        });
    let merkle_ok = flat_merkle_root_from_digests(&digests) == manifest.merkle_root_hex;
    let meta_pairs: Vec<(String, EntryMetadata)> = manifest
        .entries
        .iter()
        .map(|e| (e.rel_path.clone(), e.metadata.clone().unwrap_or_default()))
        .collect();
    let meta_refs: Vec<(&str, &EntryMetadata)> =
        meta_pairs.iter().map(|(p, m)| (p.as_str(), m)).collect();
    let metadata_ok = metadata_commitment(&meta_refs) == manifest.metadata_root_hex;

    let mut committed_paths = Vec::new();
    let committed = sha_ok && merkle_ok && metadata_ok;
    if committed {
        let commit = commit_verified_staging(cx, dest_dir, manifest, config, &staging_paths).await;
        match commit {
            Ok(paths) => committed_paths = paths,
            Err(err) => {
                let _ = crate::fs::remove_dir_all(&staging_dir).await;
                return Err(err);
            }
        }
    }
    let _ = crate::fs::remove_dir_all(&staging_dir).await;
    staging_guard.disarm();

    let receipt = ReceiveReceipt {
        committed,
        bytes_received: received,
        files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
        sha_ok,
        merkle_ok,
        symbols_accepted: 0,
        feedback_rounds: 0,
        decode_count: 0,
        decode_micros: 0,
        reason: if committed {
            None
        } else if !sha_ok {
            Some("delta per-entry SHA-256 mismatch".to_string())
        } else if !merkle_ok {
            Some("delta merkle-root mismatch".to_string())
        } else {
            Some("delta metadata commitment mismatch".to_string())
        },
        committed_paths: committed_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
    };
    send_receipt_and_close(cx, transport, config, &receipt).await?;
    if !committed {
        return Err(TransportError::Integrity(
            receipt
                .reason
                .unwrap_or_else(|| "delta verification failed".to_string()),
        ));
    }

    let _ = requested_by_key;
    Ok(ReceiveReport {
        transfer_id: manifest.transfer_id.clone(),
        bytes_received: received,
        files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
        committed,
        symbols_accepted: 0,
        feedback_rounds: 0,
        decode_count: 0,
        decode_micros: 0,
        committed_paths,
        peer,
    })
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
    // Reject symlink-traversal escapes (writing a nested entry through a
    // manifest-declared symlink) before any filesystem mutation.
    reject_symlink_traversal(&manifest)?;
    let delta_state = build_receiver_delta_state(dest_dir, &manifest, &config).await?;
    let request_frame = json_frame(FrameType::ObjectRequest, &delta_state.request)?;
    with_transport_timeout(
        cx,
        config.idle_timeout,
        "send object request",
        transport.send(&request_frame),
    )
    .await?;
    match delta_state.request.mode {
        DeltaWireMode::AlreadyInSync => {
            let complete = with_transport_timeout(
                cx,
                config.idle_timeout,
                "receive delta noop complete",
                transport.recv(),
            )
            .await?;
            if !matches!(
                complete.frame_type(),
                FrameType::ObjectComplete | FrameType::Close
            ) {
                return Err(TransportError::Unexpected {
                    got: complete.frame_type(),
                    expected: "ObjectComplete | Close",
                });
            }
            let receipt = ReceiveReceipt {
                committed: true,
                bytes_received: 0,
                files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
                sha_ok: true,
                merkle_ok: true,
                symbols_accepted: 0,
                feedback_rounds: 0,
                decode_count: 0,
                decode_micros: 0,
                reason: None,
                committed_paths: Vec::new(),
            };
            send_receipt_and_close(cx, &mut transport, &config, &receipt).await?;
            return Ok(ReceiveReport {
                transfer_id: manifest.transfer_id,
                bytes_received: 0,
                files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
                committed: true,
                symbols_accepted: 0,
                feedback_rounds: 0,
                decode_count: 0,
                decode_micros: 0,
                committed_paths: Vec::new(),
                peer,
            });
        }
        DeltaWireMode::DeltaChunks => {
            let baseline = delta_state.baseline.as_ref().ok_or_else(|| {
                TransportError::Frame("delta request missing receiver baseline".to_string())
            })?;
            return receive_delta_chunks_and_commit(
                cx,
                &mut transport,
                peer,
                dest_dir,
                &config,
                &manifest,
                baseline,
                &delta_state.request,
            )
            .await;
        }
        DeltaWireMode::FullObject => {}
    }

    // Bounded-memory streaming receive: every entry is written straight to a
    // staging file as chunks arrive, with incremental SHA-256 + content-id
    // hashing. At most one staging file handle is open at a time, and nothing
    // ever holds a whole entry (or the whole transfer) in memory — peak RSS is
    // O(chunk_size) regardless of transfer size.
    let staging_seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
    let staging_dir = dest_dir.join(format!(
        ".atp-staging-{}-{staging_seq}",
        manifest.transfer_id
    ));
    // Reclaim any leftover staging dir from a crashed prior attempt, then create.
    let _ = crate::fs::remove_dir_all(&staging_dir).await;
    crate::fs::create_dir_all(&staging_dir).await?;
    // Reclaim the staging dir even if this future is dropped before reaching a
    // cooperative cleanup path (e.g. `serve` aborting an in-flight receive task
    // via `TaskHandle::abort`, which drops the future without polling it to a
    // `return`). The cooperative exits below disarm this guard and remove the
    // directory asynchronously; only a hard drop falls back to the guard.
    let mut staging_guard = StagingDirGuard::new(staging_dir.clone());

    let mut states: Vec<StagedEntryReceive> = manifest
        .entries
        .iter()
        .enumerate()
        .map(|(i, _)| StagedEntryReceive::new(staging_dir.join(i.to_string())))
        .collect();
    let mut active: Option<(usize, crate::fs::File)> = None;
    let mut received: u64 = 0;

    // Drive the receive loop in a helper future so the staging directory is
    // always cleaned up on an error path instead of leaking partial data.
    let recv_result: Result<(), TransportError> = async {
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

                    // Close the previous entry's staging file when a new entry
                    // begins (the sender streams entries in index order).
                    let switch = matches!(&active, Some((cur, _)) if *cur != idx);
                    if switch {
                        if let Some((_, mut file)) = active.take() {
                            file.flush().await?;
                        }
                    }
                    if active.is_none() {
                        let st = &mut states[idx];
                        if st.created {
                            return Err(TransportError::Frame(format!(
                                "ObjectData entry {index} resumed out of order"
                            )));
                        }
                        if offset != 0 {
                            return Err(TransportError::Frame(format!(
                                "ObjectData entry {index} starts at offset {offset}, expected 0"
                            )));
                        }
                        let file = crate::fs::File::create(&st.staging_path).await?;
                        // Pre-size a sparse file to the full length so holes
                        // (seeked-over zero runs) and a trailing hole are
                        // preserved without growing allocation.
                        if config.sparse_files {
                            file.set_len(entry.size).await?;
                        }
                        st.mark_created();
                        active = Some((idx, file));
                    }

                    {
                        let st = &states[idx];
                        if offset != st.bytes_written {
                            return Err(TransportError::Frame(format!(
                                "ObjectData entry {index} out-of-order: got offset {offset}, expected {}",
                                st.bytes_written
                            )));
                        }
                        if st.bytes_written.saturating_add(chunk.len() as u64) > entry.size {
                            return Err(TransportError::Frame(format!(
                                "ObjectData entry {index} overruns declared size {}",
                                entry.size
                            )));
                        }
                    }
                    received = received.saturating_add(chunk.len() as u64);
                    if received > config.max_transfer_bytes {
                        return Err(TransportError::TooLarge {
                            size: received,
                            max: config.max_transfer_bytes,
                        });
                    }

                    let Some((_, file)) = active.as_mut() else {
                        return Err(TransportError::Frame(format!(
                            "internal: no active staging file for entry {index}"
                        )));
                    };
                    if config.sparse_files {
                        write_chunk_sparse(file, chunk).await?;
                    } else {
                        file.write_all(chunk).await?;
                    }
                    let st = &mut states[idx];
                    st.update_with_chunk(chunk);
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
        if let Some((_, mut file)) = active.take() {
            file.flush().await?;
        }
        Ok(())
    }
    .await;

    if let Err(e) = recv_result {
        let _ = crate::fs::remove_dir_all(&staging_dir).await;
        return Err(e);
    }

    // Finalize per-entry hashes and verify against the manifest. Zero-byte
    // entries never produced an ObjectData frame, so materialize their (empty)
    // staging file before commit.
    let mut sha_ok = true;
    let mut digests: Vec<EntryDigest> = Vec::with_capacity(states.len());
    let mut staging_paths: Vec<PathBuf> = Vec::with_capacity(states.len());
    for (entry, st) in manifest.entries.iter().zip(states) {
        let (digest, staging_path, created) = st.finalize(entry.rel_path.clone());
        if !created {
            if let Err(e) = crate::fs::File::create(&staging_path).await {
                let _ = crate::fs::remove_dir_all(&staging_dir).await;
                return Err(TransportError::from(e));
            }
        }
        if digest.size != entry.size || hex_encode(&digest.content_sha256) != entry.sha256_hex {
            sha_ok = false;
        }
        digests.push(digest);
        staging_paths.push(staging_path);
    }

    let rebuilt_root = flat_merkle_root_from_digests(&digests);
    let merkle_ok = rebuilt_root == manifest.merkle_root_hex;

    // Recompute the metadata commitment over the received manifest and verify it
    // against the sender's, so a corrupted metadata block fails closed exactly
    // like a content-merkle mismatch.
    let meta_pairs: Vec<(String, EntryMetadata)> = manifest
        .entries
        .iter()
        .map(|e| (e.rel_path.clone(), e.metadata.clone().unwrap_or_default()))
        .collect();
    let meta_refs: Vec<(&str, &EntryMetadata)> =
        meta_pairs.iter().map(|(p, m)| (p.as_str(), m)).collect();
    let metadata_ok = metadata_commitment(&meta_refs) == manifest.metadata_root_hex;

    let mut committed_paths: Vec<PathBuf> = Vec::new();
    let committed = sha_ok && merkle_ok && metadata_ok;
    if committed {
        // Commit by atomic rename from staging into the destination. The base
        // path is sanitized so a hostile `root_name` cannot escape `dest_dir`.
        let commit: Result<(), TransportError> = async {
            let base = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
            for (entry, staging_path) in manifest.entries.iter().zip(staging_paths.iter()) {
                let out_path = if manifest.is_directory {
                    join_relative(&base, &entry.rel_path)?
                } else {
                    base.clone()
                };

                // Special files (FIFO/socket/device). A FIFO is recreated via
                // `mkfifo` only when `allow_special_files` is set; everything else
                // (sockets, device nodes, or FIFOs without the opt-in) is skipped
                // and logged with no path committed, before any parent is made.
                if let Some(meta) = &entry.metadata {
                    if meta.file_kind.is_special() {
                        if matches!(meta.file_kind, FileKind::Fifo) && config.allow_special_files {
                            if let Some(parent) = out_path.parent() {
                                crate::fs::create_dir_all(parent).await?;
                            }
                            let mode = meta.unix_mode.unwrap_or(0o644);
                            let _ = crate::fs::remove_file(&out_path).await;
                            crate::net::atp::transport_common::metadata::recreate_fifo(
                                &out_path, mode,
                            )
                            .await?;
                            apply_entry_metadata_best_effort(cx, &out_path, meta).await;
                            committed_paths.push(out_path);
                            continue;
                        }
                        if cx.trace_buffer().is_some() {
                            let path_str = out_path.display().to_string();
                            let kind = format!("{:?}", meta.file_kind);
                            cx.trace_with_fields(
                                "atp_tcp_special_file_skipped",
                                &[("path", path_str.as_str()), ("kind", kind.as_str())],
                            );
                        }
                        continue;
                    }
                }

                if let Some(parent) = out_path.parent() {
                    crate::fs::create_dir_all(parent).await?;
                }

                // An empty directory commits by creating the directory (with its
                // recorded mode) rather than renaming the (empty) staged file.
                if let Some(meta) = &entry.metadata {
                    if matches!(meta.file_kind, FileKind::Directory) {
                        crate::fs::create_dir_all(&out_path).await?;
                        apply_entry_metadata_best_effort(cx, &out_path, meta).await;
                        committed_paths.push(out_path);
                        continue;
                    }
                }

                // A symlink commits by creating the link from its recorded target
                // rather than renaming the (empty) staged file into place.
                let symlink_target = entry.metadata.as_ref().and_then(|m| {
                    matches!(m.file_kind, FileKind::Symlink)
                        .then(|| m.symlink_target.clone())
                        .flatten()
                });
                if let Some(target) = symlink_target {
                    let _ = crate::fs::remove_file(&out_path).await;
                    crate::fs::symlink(&target, &out_path).await?;
                    committed_paths.push(out_path);
                    continue;
                }

                // A hardlink commits by linking to its primary — which sorts
                // earlier in the manifest and is therefore already on disk —
                // rather than writing a duplicate copy. The primary path is
                // sanitized through `join_relative` (kept under the destination).
                let hardlink_target = entry
                    .metadata
                    .as_ref()
                    .and_then(|m| m.hardlink_target.clone());
                if let Some(primary_rel) = hardlink_target {
                    let primary_path = join_relative(&base, &primary_rel)?;
                    let _ = crate::fs::remove_file(&out_path).await;
                    crate::fs::hard_link(&primary_path, &out_path).await?;
                    committed_paths.push(out_path);
                    continue;
                }

                crate::fs::rename(staging_path, &out_path).await?;

                // Apply captured metadata (mode/mtime/owner) best-effort; skips
                // (e.g. chown without privilege) are traced, never fatal.
                if let Some(meta) = &entry.metadata {
                    apply_entry_metadata_best_effort(cx, &out_path, meta).await;
                }
                committed_paths.push(out_path);
            }
            Ok(())
        }
        .await;
        if let Err(e) = commit {
            let _ = crate::fs::remove_dir_all(&staging_dir).await;
            return Err(e);
        }
    }

    // Remove the staging directory: empty after a committed rename pass, or
    // still holding the rejected data after a verification failure.
    let _ = crate::fs::remove_dir_all(&staging_dir).await;
    // Reclaimed on this cooperative path — the drop-guard backstop is no longer
    // needed, so avoid a redundant synchronous remove when this scope ends.
    staging_guard.disarm();

    let receipt = ReceiveReceipt {
        committed,
        bytes_received: received,
        files: u32::try_from(manifest.entries.len()).unwrap_or(u32::MAX),
        sha_ok,
        merkle_ok,
        symbols_accepted: 0,
        feedback_rounds: 0,
        decode_count: 0,
        decode_micros: 0,
        reason: if committed {
            None
        } else if !sha_ok {
            Some("per-entry SHA-256 mismatch".to_string())
        } else if !merkle_ok {
            Some("merkle-root mismatch".to_string())
        } else {
            Some("metadata commitment mismatch".to_string())
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
        symbols_accepted: 0,
        feedback_rounds: 0,
        decode_count: 0,
        decode_micros: 0,
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
    // A zero `accept_timeout` makes `with_transport_timeout` return immediately,
    // which would turn this accept loop into a CPU-burning busy-spin that never
    // accepts a connection (the immediate `Timeout` is matched as "no pending
    // connection" and loops). Clamp it to a sane default and use the same bounded
    // wait for both the capacity backoff sleep and the accept call.
    let accept_wait = if config.accept_timeout.is_zero() {
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
            crate::time::sleep(cx.now(), accept_wait).await;
            continue;
        }
        let accept = with_transport_timeout(cx, accept_wait, "accept", listener.accept()).await;
        match accept {
            Ok((stream, peer)) => {
                consecutive_failures = 0;
                let dest_dir = dest_dir.clone();
                let peer_id = peer_id.clone();
                let config = config.clone();
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
            metadata_root_hex: None,
            entries: vec![ManifestEntry {
                index: 0,
                rel_path: "a/b.txt".to_string(),
                size: 9,
                sha256_hex: "ff".repeat(32),
                metadata: None,
            }],
            delta_manifest: None,
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
            metadata_root_hex: None,
            entries: Vec::new(),
            delta_manifest: None,
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
    fn metadata_apply_error_is_best_effort_not_commit_fatal() {
        let cx = Cx::for_testing();
        let meta = EntryMetadata {
            unix_mode: Some(0o600),
            ..Default::default()
        };
        let missing = Path::new("/asupersync-tcp-metadata-best-effort-missing-file");

        futures_lite::future::block_on(apply_entry_metadata_best_effort(&cx, missing, &meta));
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
            metadata_root_hex: None,
            entries,
            delta_manifest: None,
        }
    }

    fn entry(index: u32, size: u64) -> ManifestEntry {
        ManifestEntry {
            index,
            rel_path: format!("f{index}"),
            size,
            sha256_hex: "0".repeat(64),
            metadata: None,
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

    fn symlink_entry(index: u32, rel: &str, target: &str) -> ManifestEntry {
        ManifestEntry {
            index,
            rel_path: rel.to_string(),
            size: 0,
            sha256_hex: "0".repeat(64),
            metadata: Some(EntryMetadata {
                file_kind: FileKind::Symlink,
                symlink_target: Some(target.to_string()),
                ..Default::default()
            }),
        }
    }

    fn named_entry(index: u32, rel: &str) -> ManifestEntry {
        ManifestEntry {
            index,
            rel_path: rel.to_string(),
            size: 0,
            sha256_hex: "0".repeat(64),
            metadata: None,
        }
    }

    #[test]
    fn reject_symlink_traversal_blocks_entries_nested_under_a_symlink() {
        // A file written through a manifest-declared symlink would escape dest.
        let bad = manifest_with(
            vec![symlink_entry(0, "x", "/etc"), named_entry(1, "x/payload")],
            0,
        );
        assert!(
            matches!(
                reject_symlink_traversal(&bad),
                Err(TransportError::Source(_))
            ),
            "entry nested under a symlink must be rejected"
        );

        // Nested symlink-under-symlink is also rejected.
        let bad2 = manifest_with(
            vec![symlink_entry(0, "a", "/x"), symlink_entry(1, "a/b", "/y")],
            0,
        );
        assert!(reject_symlink_traversal(&bad2).is_err());
    }

    #[test]
    fn reject_symlink_traversal_allows_siblings_and_links_without_nesting() {
        // "xy" is a sibling of symlink "x", not nested under it; a normal link
        // with no entries beneath it is fine.
        let ok = manifest_with(
            vec![
                symlink_entry(0, "x", "data.txt"),
                named_entry(1, "xy"),
                named_entry(2, "data.txt"),
            ],
            0,
        );
        assert!(reject_symlink_traversal(&ok).is_ok());
        // No symlinks at all: trivially ok.
        let plain = manifest_with(vec![entry(0, 10), entry(1, 20)], 30);
        assert!(reject_symlink_traversal(&plain).is_ok());
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

    #[test]
    fn staging_dir_guard_reclaims_on_hard_drop_unless_disarmed() {
        let base = std::env::temp_dir().join(format!("atp-staging-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        // An armed guard reclaims the staging dir when dropped without a
        // cooperative cleanup (the `serve`-abort / hard-future-drop path).
        let armed = base.join("armed");
        std::fs::create_dir_all(&armed).expect("create armed staging dir");
        drop(StagingDirGuard::new(armed.clone()));
        assert!(
            !armed.exists(),
            "armed StagingDirGuard must reclaim the staging dir on drop"
        );

        // A disarmed guard leaves the directory in place (the cooperative path
        // already removed it asynchronously, so the backstop must not run).
        let disarmed = base.join("disarmed");
        std::fs::create_dir_all(&disarmed).expect("create disarmed staging dir");
        let mut guard = StagingDirGuard::new(disarmed.clone());
        guard.disarm();
        drop(guard);
        assert!(
            disarmed.exists(),
            "disarmed StagingDirGuard must leave the staging dir in place"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
