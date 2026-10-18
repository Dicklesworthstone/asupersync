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
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::atp::delta::{
    CasChunkRef, ContentAddressedChunkStore as DeltaPlannerStore, DeltaResyncFallbackReason,
    DeltaResyncMode, PersistentChunkManifest, plan_incremental_resync,
};
use crate::atp::object::{ContentId, MetadataPolicy, ObjectId};
use crate::atp::safety::{
    portable_path_collision_key, validate_portable_path_component, validate_portable_path_set,
    validate_portable_relative_path,
};
use crate::net::atp::transport_common::codec::{
    self, CodecAccept, CodecOffer, CompressionMode, DecodeCapability, EntryCompression,
};
use crate::net::atp::transport_common::delta::ATP_DELTA_CHUNK_MANIFEST_SCHEMA;
use crate::net::atp::transport_common::metadata::{
    DeferredParentSyncs, HardlinkIdentity, commit_hardlink_transactionally,
    commit_symlink_transactionally, path_is_link_or_reparse, path_is_link_or_reparse_sync,
    validate_entry_metadata_for_receive, validate_symlink_metadata_for_receive,
    write_sparse_zero_runs,
};
#[cfg(not(windows))]
use crate::net::atp::transport_common::apply_entry_metadata_sync;
#[cfg(not(windows))]
use crate::net::atp::transport_common::metadata::install_staged_regular_file_sync;
#[cfg(test)]
use crate::net::atp::transport_common::metadata::{
    DirectoryMetadataEntry, SymlinkTargetInfo, SymlinkTargetKind, SymlinkTargetSemantics,
};
use crate::net::atp::transport_common::streaming::collect_entries_with_policy;
use crate::net::atp::transport_common::{
    DeltaChunkWire, DeltaManifestWire, DeltaObjectRequest, DeltaWireMode,
    DirectoryMetadataManifest, EntryDigest, EntryMetadata, FileKind, FilterSet,
    MetadataApplyReport, MirrorError, MirrorPolicy, SourceEntry, StagedEntryReceive,
    StreamingError, apply_entry_metadata, capture_directory_metadata_manifest,
    flat_merkle_root_from_digests, hash_file_streaming, hex_encode, metadata_commitment,
    mirror_dest, read_entry_metadata,
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
use crate::util::entropy::{EntropySource, OsEntropy};

/// Protocol identifier carried in the handshake; bump on wire-incompatible
/// changes.
pub const ATP_TCP_PROTOCOL: u32 = 2;

/// Default bulk-data chunk size. Kept comfortably below the 1 MiB
/// `MAX_FRAME_SIZE` so a chunk plus its frame header always fits one frame.
pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

/// The largest raw chunk a receiver decodes from one compressed data frame.
/// It equals `MAX_FRAME_SIZE`, which no uncompressed chunk can exceed either,
/// so a compressed chunk never needs a larger buffer than a raw one.
const MAX_COMPRESSED_CHUNK_RAW: u32 = 1 << 20;

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
    /// Receiver-side mirror (`rsync --delete`) policy for committed directory
    /// transfers. Defaults to [`MirrorPolicy::default`], which is a dry-run and
    /// deletes nothing; callers must explicitly opt in to destructive mirroring.
    pub mirror_policy: MirrorPolicy,
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
            mirror_policy: MirrorPolicy::default(),
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

impl From<MirrorError> for TransportError {
    fn from(err: MirrorError) -> Self {
        match err {
            MirrorError::Io(err) => Self::Io(err),
            MirrorError::Cancelled => Self::Cancelled,
            other => Self::Frame(format!("mirror reconciliation failed: {other}")),
        }
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

/// One logical file packed into a combined transfer entry.
///
/// When [`ManifestEntry::members`] is non-empty the entry's content is the
/// byte concatenation of its members in `offset` order; the receiver splits
/// the verified entry back into the member files on commit. This amortizes
/// the per-entry stream/staging/commit overhead that makes many-small-file
/// trees slow on the QUIC tier (mirrors the RaptorQ tier's E-15 coalescing,
/// plus per-member metadata because this wire family preserves metadata).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackedMember {
    /// Path of this file relative to the transfer root.
    pub rel_path: String,
    /// Byte offset of this file within the combined entry content.
    pub offset: u64,
    /// Byte length of this file.
    pub len: u64,
    /// Lowercase hex SHA-256 of this file's content.
    pub sha256_hex: String,
    /// Captured filesystem metadata for this member (always a regular file;
    /// symlinks/directories/hardlinks are never packed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<EntryMetadata>,
}

/// One file within a transfer manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    /// Files packed into this entry. Empty = a normal single-file entry whose
    /// content IS the file (prior wire format, byte-identical thanks to
    /// `skip_serializing_if`). Non-empty = this entry is a combined object and
    /// these members are extracted by offset on receive; the entry itself then
    /// carries no metadata and its `rel_path` is an internal pack name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<PackedMember>,
}

/// Transfer manifest carried in the `ObjectManifest` frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    /// Independent commitment over entry and directory filesystem metadata
    /// (sorted by path), present only when at least one path carries metadata.
    /// The receiver recomputes and verifies it so metadata-block corruption
    /// fails closed, the same way a content-merkle mismatch does. `None` for a
    /// portable transfer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_root_hex: Option<String>,
    /// Policy-selected metadata for the transfer root and otherwise implicit
    /// non-root directories. Kept separate from content entries so directory
    /// fidelity does not change file/report counts. Absent on legacy wires and
    /// portable transfers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_metadata: Option<DirectoryMetadataManifest>,
    /// File entries in manifest order.
    pub entries: Vec<ManifestEntry>,
    /// Optional delta chunk manifest. Old full-transfer behavior remains the
    /// fallback whenever this is absent or the receiver declines the delta path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_manifest: Option<DeltaManifestWire>,
}

/// Receipt returned by the receiver in the `Proof` frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    /// What this side can decode when it receives (br-asupersync-t1fblr.16).
    decode: DecodeCapability,
    /// The payload codec both sides agreed on in the handshake, if any. Only
    /// then may data frames carry compressed chunks.
    chunk_codec: Option<CodecAccept>,
    /// What the sender asked for, which decides the chunks it tries to
    /// compress once a codec is agreed (br-asupersync-t1fblr.24).
    compression: CompressionMode,
    /// Chunks of a file the sender compresses at once
    /// (br-asupersync-t1fblr.25).
    #[cfg_attr(not(feature = "zstd"), allow(dead_code))]
    compression_parallelism: usize,
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
            decode: codec::local_decode_capability(MAX_COMPRESSED_CHUNK_RAW),
            chunk_codec: None,
            compression: CompressionMode::Off,
            compression_parallelism: codec::DEFAULT_COMPRESSION_PARALLELISM,
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
        if wire.schema != ATP_DELTA_CHUNK_MANIFEST_SCHEMA {
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
            schema: ATP_DELTA_CHUNK_MANIFEST_SCHEMA.to_string(),
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
        let (_, _, entries) = collect_entries_with_policy(source, &config.metadata_policy).await?;
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
    let mut entry = EntryCompression::new(transport.compression, &path.to_string_lossy());
    loop {
        let n = file
            .read(buf)
            .await
            .map_err(|e| TransportError::Source(format!("{}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        let frame = chunk_frame(
            transport.chunk_codec.as_ref(),
            &mut entry,
            index,
            offset,
            &buf[..n],
        )?;
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

/// An entry whose chunks are not all sent yet, in
/// [`send_full_entries_pipelined`].
#[cfg(feature = "zstd")]
struct OpenEntry {
    /// The manifest size, reported as progress once the entry is sent.
    size: u64,
    /// Chunks queued in the pipeline so far.
    queued: usize,
    /// Chunks sent so far.
    sent: usize,
    /// The whole file has been read and queued.
    read_all: bool,
}

/// The pipelined counterpart of [`send_full_entries_streaming`]'s loop, for a
/// session that agreed on a codec (br-asupersync-t1fblr.25).
///
/// Chunks of consecutive files share one [`codec::ChunkPipeline`]: up to
/// `compression_parallelism` compress at once on the runtime's blocking pool
/// and go out in the order they were read, so a tree of small files
/// compresses in parallel too. Memory is bounded by that many chunks in
/// flight, raw and compressed, plus the one being read. Progress is reported
/// as before: once per regular entry, in order, after its last chunk is sent.
#[cfg(feature = "zstd")]
async fn send_full_entries_pipelined<S>(
    cx: &Cx,
    transport: &mut FrameTransport<S>,
    entries: &[SourceEntry],
    metadatas: &[EntryMetadata],
    digests: &[EntryDigest],
    config: &TransferConfig,
    chunk_len: usize,
    accept: CodecAccept,
    on_progress: &mut impl FnMut(u64, u64),
) -> Result<u64, TransportError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let total_bytes = digests
        .iter()
        .fold(0u64, |sum, digest| sum.saturating_add(digest.size));
    let mut sent_bytes = 0u64;
    let mut pipeline = codec::ChunkPipeline::new(accept, transport.compression_parallelism);
    // Buffers of chunks already sent, reused for the next reads.
    let mut spare: Vec<Vec<u8>> = Vec::new();
    let mut open: std::collections::VecDeque<OpenEntry> = std::collections::VecDeque::new();
    // The entry being read and its decisions: only its outcomes still decide.
    let mut current = u32::MAX;
    let mut decisions = EntryCompression::new(CompressionMode::Off, "");
    for (i, entry) in entries.iter().enumerate() {
        cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
        if !matches!(metadatas[i].file_kind, FileKind::Regular)
            || metadatas[i].hardlink_target.is_some()
        {
            continue;
        }
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let mut file = crate::fs::File::open(&entry.abs_path)
            .await
            .map_err(|e| TransportError::Source(format!("{}: {e}", entry.abs_path.display())))?;
        current = index;
        decisions = EntryCompression::new(transport.compression, &entry.abs_path.to_string_lossy());
        open.push_back(OpenEntry {
            size: digests[i].size,
            queued: 0,
            sent: 0,
            read_all: false,
        });
        let mut offset: u64 = 0;
        loop {
            while pipeline.is_full() {
                send_pipelined_chunk(
                    cx,
                    transport,
                    config,
                    &mut pipeline,
                    current,
                    &mut decisions,
                    &mut open,
                    &mut spare,
                )
                .await?;
                report_sent_entries(&mut open, &mut sent_bytes, total_bytes, on_progress);
            }
            let mut raw = spare.pop().unwrap_or_default();
            raw.resize(chunk_len.max(1), 0);
            let n = file.read(&mut raw).await.map_err(|e| {
                TransportError::Source(format!("{}: {e}", entry.abs_path.display()))
            })?;
            if n == 0 {
                break;
            }
            raw.truncate(n);
            pipeline.push(cx, &mut decisions, index, offset, raw);
            offset = offset.saturating_add(n as u64);
            if let Some(last) = open.back_mut() {
                last.queued += 1;
            }
        }
        if let Some(last) = open.back_mut() {
            last.read_all = true;
        }
        report_sent_entries(&mut open, &mut sent_bytes, total_bytes, on_progress);
    }
    while !open.is_empty() {
        if !send_pipelined_chunk(
            cx,
            transport,
            config,
            &mut pipeline,
            current,
            &mut decisions,
            &mut open,
            &mut spare,
        )
        .await?
        {
            break;
        }
        report_sent_entries(&mut open, &mut sent_bytes, total_bytes, on_progress);
    }
    on_progress(total_bytes, total_bytes);
    Ok(total_bytes)
}

/// Sends the oldest chunk of `pipeline` once it is ready and counts it
/// against its entry in `open`. `false` when the pipeline was empty.
#[cfg(feature = "zstd")]
async fn send_pipelined_chunk<S>(
    cx: &Cx,
    transport: &mut FrameTransport<S>,
    config: &TransferConfig,
    pipeline: &mut codec::ChunkPipeline,
    current: u32,
    decisions: &mut EntryCompression,
    open: &mut std::collections::VecDeque<OpenEntry>,
    spare: &mut Vec<Vec<u8>>,
) -> Result<bool, TransportError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let Some(chunk) = pipeline.next(current, decisions).await else {
        return Ok(false);
    };
    let chunk = chunk.map_err(|error| match error {
        crate::runtime::JoinError::Cancelled(_) => TransportError::Cancelled,
        other => TransportError::Frame(format!("compressing a chunk failed: {other}")),
    })?;
    let frame = match &chunk.compressed {
        Some((record, payload)) => {
            compressed_data_frame(chunk.index, chunk.offset, *record, payload)?
        }
        None => data_frame(chunk.index, chunk.offset, &chunk.raw)?,
    };
    with_transport_timeout(
        cx,
        config.idle_timeout,
        "send data frame",
        transport.send(&frame),
    )
    .await?;
    // Chunks leave in the order they were read, so this one belongs to the
    // oldest entry that still has chunks to send.
    if let Some(entry) = open.iter_mut().find(|entry| entry.sent < entry.queued) {
        entry.sent += 1;
    }
    spare.push(chunk.raw);
    Ok(true)
}

/// Reports, in order, every leading entry of `open` that is read to the end
/// with all its chunks sent, as [`send_full_entries_streaming`] does after
/// each entry.
#[cfg(feature = "zstd")]
fn report_sent_entries(
    open: &mut std::collections::VecDeque<OpenEntry>,
    sent_bytes: &mut u64,
    total_bytes: u64,
    on_progress: &mut impl FnMut(u64, u64),
) {
    while open
        .front()
        .is_some_and(|entry| entry.read_all && entry.sent == entry.queued)
    {
        if let Some(entry) = open.pop_front() {
            *sent_bytes = sent_bytes.saturating_add(entry.size);
            on_progress(*sent_bytes, total_bytes);
        }
    }
}

fn transfer_manifest_metadata_commitment(manifest: &TransferManifest) -> Option<String> {
    let default_metadata = EntryMetadata::default();
    let mut pairs = manifest
        .entries
        .iter()
        .map(|entry| {
            (
                entry.rel_path.as_str(),
                entry.metadata.as_ref().unwrap_or(&default_metadata),
            )
        })
        .collect::<Vec<_>>();
    if let Some(directory_metadata) = &manifest.directory_metadata {
        pairs.extend(directory_metadata.commitment_pairs());
    }
    metadata_commitment(&pairs)
}

fn strict_ancestor_paths<'a>(paths: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    let mut ancestors = BTreeSet::new();
    for path in paths {
        let mut components = path.split('/').peekable();
        let mut rendered = String::new();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                break;
            }
            if !rendered.is_empty() {
                rendered.push('/');
            }
            rendered.push_str(component);
            ancestors.insert(rendered.clone());
        }
    }
    ancestors
}

fn validate_directory_metadata_value(
    rel_path: &str,
    metadata: &EntryMetadata,
    config: &TransferConfig,
) -> Result<(), TransportError> {
    if !matches!(metadata.file_kind, FileKind::Directory) {
        return Err(TransportError::Frame(format!(
            "directory metadata entry {rel_path} declares non-directory kind {:?}",
            metadata.file_kind
        )));
    }
    if metadata.hardlink_target.is_some() {
        return Err(TransportError::Frame(format!(
            "directory metadata entry {rel_path} declares a hardlink target"
        )));
    }
    if metadata.unix_mode.is_none()
        && metadata.mtime_unix_secs.is_none()
        && metadata.mtime_nanos.is_none()
        && metadata.uid.is_none()
        && metadata.gid.is_none()
        && metadata.windows_attributes.is_none()
        && metadata.xattrs.is_empty()
    {
        return Err(TransportError::Frame(format!(
            "directory metadata entry {rel_path} carries no fidelity fields"
        )));
    }
    validate_entry_metadata_for_receive(rel_path, metadata, &config.metadata_policy).map_err(
        |error| {
            TransportError::Frame(format!(
                "directory metadata entry {rel_path} has invalid metadata: {error}"
            ))
        },
    )
}

fn validate_directory_metadata_manifest(
    manifest: &TransferManifest,
    config: &TransferConfig,
) -> Result<(), TransportError> {
    let Some(directory_metadata) = &manifest.directory_metadata else {
        return Ok(());
    };
    if directory_metadata.is_empty() {
        return Err(TransportError::Frame(
            "manifest carries a non-canonical empty directory_metadata block".to_string(),
        ));
    }
    if !manifest.is_directory {
        return Err(TransportError::Frame(
            "single-file transfer declares directory metadata".to_string(),
        ));
    }
    // Packed members were rejected in the content-entry loop above, so every
    // TCP `ManifestEntry` is already one logical entry for this combined bound.
    if manifest
        .entries
        .len()
        .saturating_add(directory_metadata.entries.len())
        > MAX_MANIFEST_ENTRIES
    {
        return Err(TransportError::Frame(format!(
            "manifest declares {} combined content and directory metadata entries (max {MAX_MANIFEST_ENTRIES})",
            manifest
                .entries
                .len()
                .saturating_add(directory_metadata.entries.len())
        )));
    }
    if let Some(root) = &directory_metadata.root {
        validate_directory_metadata_value(".", root, config)?;
    }
    if directory_metadata
        .entries
        .windows(2)
        .any(|pair| pair[0].rel_path >= pair[1].rel_path)
    {
        return Err(TransportError::Frame(
            "directory metadata entries are not in strictly increasing path order".to_string(),
        ));
    }
    let mut directory_paths = BTreeMap::<String, String>::new();
    let mut directory_prefixes = BTreeMap::<String, String>::new();
    for directory in &directory_metadata.entries {
        validate_manifest_rel_path(&directory.rel_path)?;
        let path_key = portable_path_collision_key(&directory.rel_path);
        if let Some(existing) = directory_paths.insert(path_key, directory.rel_path.clone()) {
            return Err(TransportError::Frame(format!(
                "duplicate or case-colliding directory metadata paths: {existing} and {}",
                directory.rel_path
            )));
        }

        let mut rendered_prefix = String::new();
        for component in directory.rel_path.split('/') {
            if !rendered_prefix.is_empty() {
                rendered_prefix.push('/');
            }
            rendered_prefix.push_str(component);
            let prefix_key = portable_path_collision_key(&rendered_prefix);
            if let Some(existing) = directory_prefixes.get(&prefix_key) {
                if existing != &rendered_prefix {
                    return Err(TransportError::Frame(format!(
                        "case-colliding directory metadata prefixes: {existing} and {rendered_prefix}"
                    )));
                }
            } else {
                directory_prefixes.insert(prefix_key, rendered_prefix.clone());
            }
        }
    }

    let content_by_key = manifest
        .entries
        .iter()
        .map(|entry| (portable_path_collision_key(&entry.rel_path), entry))
        .collect::<BTreeMap<_, _>>();
    let content_ancestors =
        strict_ancestor_paths(manifest.entries.iter().map(|entry| entry.rel_path.as_str()));
    for directory in &directory_metadata.entries {
        validate_directory_metadata_value(&directory.rel_path, &directory.metadata, config)?;
        let directory_key = portable_path_collision_key(&directory.rel_path);
        if let Some(content_entry) = content_by_key.get(&directory_key) {
            return Err(TransportError::Frame(format!(
                "directory metadata path {} aliases logical content entry {}",
                directory.rel_path, content_entry.rel_path
            )));
        }

        if !content_ancestors.contains(&directory.rel_path) {
            return Err(TransportError::Frame(format!(
                "directory metadata path {} is not represented by the transfer tree",
                directory.rel_path
            )));
        }
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
    validate_portable_path_component(&manifest.root_name).map_err(|_| {
        TransportError::Source(format!("unsafe manifest root_name: {}", manifest.root_name))
    })?;
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
    let mut seen_rel_paths = BTreeMap::<String, (String, FileKind, bool, EntryMetadata)>::new();
    let empty_sha_hex = hex_encode(&Sha256::digest(b""));
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
                if !entry.members.is_empty() {
                    return Err(TransportError::Frame(format!(
                        "TCP manifest entry {} unexpectedly contains packed members",
                        entry.rel_path
                    )));
                }
                if entry.sha256_hex.len() != 64
                    || !entry.sha256_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(TransportError::Frame(format!(
                        "manifest entry {} has invalid sha256_hex",
                        entry.rel_path
                    )));
                }

                if entry.metadata.as_ref().is_some_and(EntryMetadata::is_bare) {
                    return Err(TransportError::Frame(format!(
                        "manifest entry {} carries non-canonical bare metadata",
                        entry.rel_path
                    )));
                }
                let metadata = entry.metadata.clone().unwrap_or_default();
                if metadata.hardlink_target.is_some()
                    && !matches!(metadata.file_kind, FileKind::Regular)
                {
                    return Err(TransportError::Frame(format!(
                        "manifest entry {} declares a hardlink on non-regular kind {:?}",
                        entry.rel_path, metadata.file_kind
                    )));
                }
                validate_entry_metadata_for_receive(
                    &entry.rel_path,
                    &metadata,
                    &config.metadata_policy,
                )
                .map_err(
                    |error| {
                        TransportError::Frame(format!(
                            "manifest entry {} has invalid metadata: {error}",
                            entry.rel_path
                        ))
                    },
                )?;
                if metadata.hardlink_target.is_some() && !config.preserve_hardlinks {
                    return Err(TransportError::Frame(format!(
                        "manifest hardlink entry {} is denied by receiver policy",
                        entry.rel_path
                    )));
                }
                if let Some(primary_rel) = &metadata.hardlink_target {
                    validate_manifest_rel_path(primary_rel)?;
                    let primary_key = portable_path_collision_key(primary_rel);
                    let primary_metadata = seen_rel_paths.get(&primary_key).and_then(
                        |(seen_path, seen_kind, seen_is_hardlink, seen_metadata)| {
                            (seen_path == primary_rel
                                && matches!(seen_kind, FileKind::Regular)
                                && !seen_is_hardlink)
                                .then_some(seen_metadata)
                        },
                    );
                    if primary_rel == &entry.rel_path || primary_metadata.is_none() {
                        return Err(TransportError::Frame(format!(
                            "manifest hardlink entry {} targets missing, aliased, later, or non-primary entry {}",
                            entry.rel_path, primary_rel
                        )));
                    }
                    let mut alias_metadata = metadata.clone();
                    alias_metadata.hardlink_target = None;
                    if primary_metadata != Some(&alias_metadata) {
                        return Err(TransportError::Frame(format!(
                            "manifest hardlink entry {} declares metadata different from primary {}",
                            entry.rel_path, primary_rel
                        )));
                    }
                }
                if (!matches!(metadata.file_kind, FileKind::Regular)
                    || metadata.hardlink_target.is_some())
                    && (entry.size != 0 || entry.sha256_hex != empty_sha_hex)
                {
                    return Err(TransportError::Frame(format!(
                        "manifest metadata-only entry {} must carry zero content",
                        entry.rel_path
                    )));
                }

                let path_key = portable_path_collision_key(&entry.rel_path);
                if seen_rel_paths
                    .insert(
                        path_key,
                        (
                            entry.rel_path.clone(),
                            metadata.file_kind,
                            metadata.hardlink_target.is_some(),
                            metadata.clone(),
                        ),
                    )
                    .is_some()
                {
                    return Err(TransportError::Frame(format!(
                        "duplicate manifest rel_path (including case collision): {}",
                        entry.rel_path
                    )));
                }
                acc.checked_add(entry.size).ok_or_else(|| {
                    TransportError::Frame("manifest entry sizes overflow u64".to_string())
                })
            })?;
    validate_portable_path_set(manifest.entries.iter().map(|entry| entry.rel_path.as_str()))
        .map_err(TransportError::Frame)?;
    validate_directory_metadata_manifest(manifest, config)?;
    if declared_total > config.max_transfer_bytes {
        return Err(TransportError::TooLarge {
            size: declared_total,
            max: config.max_transfer_bytes,
        });
    }
    if declared_total != manifest.total_bytes {
        return Err(TransportError::Frame(format!(
            "manifest total_bytes {} does not match entry sum {declared_total}",
            manifest.total_bytes
        )));
    }
    if manifest.merkle_root_hex.len() != 64
        || !manifest
            .merkle_root_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(TransportError::Frame(
            "manifest merkle_root_hex is not a 64-byte hex digest".to_string(),
        ));
    }
    if manifest
        .metadata_root_hex
        .as_ref()
        .is_some_and(|root| root.len() != 64 || !root.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(TransportError::Frame(
            "manifest metadata_root_hex is not a 64-byte hex digest".to_string(),
        ));
    }
    if transfer_manifest_metadata_commitment(manifest) != manifest.metadata_root_hex {
        return Err(TransportError::Frame(
            "manifest metadata commitment mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_manifest_rel_path(rel: &str) -> Result<(), TransportError> {
    validate_portable_relative_path(rel)
        .map_err(|_| TransportError::Source(format!("unsafe manifest rel_path: {rel}")))
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
        let p_key = portable_path_collision_key(p);
        for sym in &symlink_paths {
            let sym_key = portable_path_collision_key(sym);
            // `p` is nested under symlink `sym` iff `sym` is a strict,
            // component-aligned prefix of `p` (so `p` would be written through
            // the link). The symlink entry itself (`p == sym`) is fine.
            if p_key.len() > sym_key.len()
                && p_key.as_bytes()[sym_key.len()] == b'/'
                && p_key.starts_with(&sym_key)
            {
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

/// An `ObjectData` frame for `chunk`, the bytes at `offset` of entry `index`.
/// When the session negotiated a codec, `entry` decides to try, and
/// compressing makes the chunk smaller, the payload carries the compressed
/// chunk and the frame a [`codec::CHUNK_CODEC_EXTENSION`] record; otherwise
/// the frame is byte-identical to [`data_frame`]'s.
#[cfg(feature = "zstd")]
fn chunk_frame(
    accept: Option<&CodecAccept>,
    entry: &mut EntryCompression,
    index: u32,
    offset: u64,
    chunk: &[u8],
) -> Result<Frame, TransportError> {
    if let Some((record, compressed)) =
        accept.and_then(|accept| entry.compress(accept, offset, chunk))
    {
        return compressed_data_frame(index, offset, record, &compressed);
    }
    data_frame(index, offset, chunk)
}

/// The `ObjectData` frame carrying `payload`, the compressed chunk at
/// `offset` of entry `index`, with its [`codec::CHUNK_CODEC_EXTENSION`]
/// record.
#[cfg(feature = "zstd")]
fn compressed_data_frame(
    index: u32,
    offset: u64,
    record: codec::ChunkCodec,
    payload: &[u8],
) -> Result<Frame, TransportError> {
    let mut frame = data_frame(index, offset, payload)?;
    frame
        .header
        .extensions
        .insert(codec::CHUNK_CODEC_EXTENSION, record.to_bytes());
    Ok(frame)
}

/// Without the `zstd` feature no codec is ever negotiated, so every chunk is
/// sent raw.
#[cfg(not(feature = "zstd"))]
fn chunk_frame(
    _accept: Option<&CodecAccept>,
    _entry: &mut EntryCompression,
    index: u32,
    offset: u64,
    chunk: &[u8],
) -> Result<Frame, TransportError> {
    data_frame(index, offset, chunk)
}

/// The raw bytes an `ObjectData` frame carries: its payload, or, when the
/// frame has a [`codec::CHUNK_CODEC_EXTENSION`] record, the payload
/// decompressed into `scratch`. `remaining` is the most the frame may carry; a
/// compressed chunk that declares more is refused before it is decoded, and a
/// compressed chunk on a session without a negotiated codec is refused too.
fn raw_chunk<'a>(
    frame: &Frame,
    accept: Option<&CodecAccept>,
    remaining: u64,
    payload: &'a [u8],
    scratch: &'a mut Vec<u8>,
) -> Result<&'a [u8], TransportError> {
    let Some(record) = frame.header.extensions.get(&codec::CHUNK_CODEC_EXTENSION) else {
        return Ok(payload);
    };
    codec::decompress_chunk(record, accept, remaining, payload, scratch)
        .map_err(|error| TransportError::Frame(format!("ObjectData chunk: {error}")))?;
    Ok(scratch.as_slice())
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
    metadata_matches_sender: bool,
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
    if manifest.schema != ATP_DELTA_CHUNK_MANIFEST_SCHEMA {
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
        schema: ATP_DELTA_CHUNK_MANIFEST_SCHEMA.to_string(),
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
        // A whole `chunk_size` chunk per iteration (asupersync-u4j7sr): one
        // read of `crate::fs::File` returns at most 128 KiB.
        let n = crate::net::atp::transport_common::delta::read_full_chunk(&mut file, &mut buf)
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
    #[cfg(feature = "zstd")]
    if let Some(accept) = transport.chunk_codec {
        let chunk_len = read_buf.len();
        return send_full_entries_pipelined(
            cx,
            transport,
            entries,
            metadatas,
            digests,
            config,
            chunk_len,
            accept,
            &mut on_progress,
        )
        .await;
    }
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
        // Delta chunks are scattered, so each is decided on its own: by its
        // entry's name, and at offset 0 by its first bytes.
        let mut decisions = EntryCompression::new(transport.compression, &chunk.rel_path);
        let frame = chunk_frame(
            transport.chunk_codec.as_ref(),
            &mut decisions,
            chunk.entry_index,
            chunk.entry_offset,
            &bytes,
        )?;
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
    delta_manifest_validation::validate(manifest, delta_manifest)?;
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

    let Some(baseline) = build_receiver_delta_baseline(
        dest_dir,
        manifest,
        delta_manifest,
        config,
        MAX_RECEIVER_DELTA_BASELINE_CHUNKS,
    )
    .await?
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
        DeltaResyncMode::AlreadyInSync if !baseline.metadata_matches_sender => {
            DeltaObjectRequest::full(
                plan.sender_merkle_root.to_hex(),
                receiver_merkle_root_hex,
                "delta_metadata_changed",
            )
        }
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
    entry
        .metadata
        .as_ref()
        .is_some_and(|metadata| !metadata_is_content_delta_compatible(metadata))
}

fn metadata_is_content_delta_compatible(metadata: &EntryMetadata) -> bool {
    const WINDOWS_FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;

    matches!(metadata.file_kind, FileKind::Regular)
        && metadata
            .windows_attributes
            .is_none_or(|attributes| attributes & !WINDOWS_FILE_ATTRIBUTE_ARCHIVE == 0)
        && metadata.symlink_target.is_none()
        && metadata.symlink_target_info.is_none()
        && metadata.hardlink_target.is_none()
        && metadata.xattrs.is_empty()
}

fn receiver_metadata_matches_sender(
    entries: &[ManifestEntry],
    receiver_metadata: &BTreeMap<String, EntryMetadata>,
) -> bool {
    entries.len() == receiver_metadata.len()
        && entries.iter().all(|entry| {
            receiver_metadata
                .get(&entry.rel_path)
                .is_some_and(|observed| {
                    let default_metadata = EntryMetadata::default();
                    receiver_materializable_metadata_matches(
                        entry.metadata.as_ref().unwrap_or(&default_metadata),
                        observed,
                    )
                })
        })
}

fn receiver_materializable_metadata_matches(
    expected: &EntryMetadata,
    observed: &EntryMetadata,
) -> bool {
    if expected.file_kind != observed.file_kind
        || expected.symlink_target != observed.symlink_target
        || expected.symlink_target_info != observed.symlink_target_info
        || expected.hardlink_target != observed.hardlink_target
    {
        return false;
    }

    let mut matches = true;
    #[cfg(any(unix, windows))]
    {
        if let Some(expected_seconds) = expected.mtime_unix_secs {
            matches &= observed.mtime_unix_secs == Some(expected_seconds)
                && observed.mtime_nanos.unwrap_or(0) == expected.mtime_nanos.unwrap_or(0);
        } else if let Some(expected_nanos) = expected.mtime_nanos {
            matches &= observed.mtime_nanos == Some(expected_nanos);
        }
    }
    #[cfg(unix)]
    {
        if let Some(expected_mode) = expected.unix_mode {
            matches &= observed.unix_mode == Some(expected_mode);
        }
        if let (Some(expected_uid), Some(expected_gid)) = (expected.uid, expected.gid) {
            matches &= observed.uid == Some(expected_uid) && observed.gid == Some(expected_gid);
        }
        matches &= expected
            .xattrs
            .iter()
            .all(|(name, value)| observed.xattrs.get(name) == Some(value));
    }
    #[cfg(windows)]
    {
        if let Some(expected_attributes) = expected.windows_attributes {
            matches &= observed.windows_attributes == Some(expected_attributes);
        }
    }
    matches
}

fn metadata_has_receiver_materializable_fidelity(metadata: &EntryMetadata) -> bool {
    let mut materializable = false;
    #[cfg(any(unix, windows))]
    {
        materializable |= metadata.mtime_unix_secs.is_some() || metadata.mtime_nanos.is_some();
    }
    #[cfg(unix)]
    {
        materializable |= metadata.unix_mode.is_some()
            || (metadata.uid.is_some() && metadata.gid.is_some())
            || !metadata.xattrs.is_empty();
    }
    #[cfg(windows)]
    {
        materializable |= metadata.windows_attributes.is_some();
    }
    materializable
}

fn receiver_directory_metadata_matches_sender(
    expected: Option<&DirectoryMetadataManifest>,
    observed: Option<&DirectoryMetadataManifest>,
) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    if let Some(expected_root) = expected
        .root
        .as_ref()
        .filter(|metadata| metadata_has_receiver_materializable_fidelity(metadata))
        && !observed
            .and_then(|metadata| metadata.root.as_ref())
            .is_some_and(|observed_root| {
                receiver_materializable_metadata_matches(expected_root, observed_root)
            })
    {
        return false;
    }
    let observed_entries = observed
        .map(|metadata| {
            metadata
                .entries
                .iter()
                .map(|entry| (entry.rel_path.as_str(), &entry.metadata))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    expected
        .entries
        .iter()
        .filter(|entry| metadata_has_receiver_materializable_fidelity(&entry.metadata))
        .all(|expected_entry| {
            observed_entries
                .get(expected_entry.rel_path.as_str())
                .is_some_and(|observed_metadata| {
                    receiver_materializable_metadata_matches(
                        &expected_entry.metadata,
                        observed_metadata,
                    )
                })
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

/// Most chunks a receiver splits its existing destination into for a delta.
/// The sender picks the chunk size, and each chunk costs the receiver a planner
/// entry, a CAS insert and a read, so a finer baseline falls back to a full
/// transfer. 4 Mi chunks are 1 TiB at the default chunk size.
const MAX_RECEIVER_DELTA_BASELINE_CHUNKS: u64 = 1 << 22;

async fn build_receiver_delta_baseline(
    dest_dir: &Path,
    manifest: &TransferManifest,
    delta_manifest: &DeltaManifestWire,
    config: &TransferConfig,
    max_chunks: u64,
) -> Result<Option<ReceiverDeltaBaseline>, TransportError> {
    let base = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
    if !base.exists() {
        return Ok(None);
    }
    let (_, receiver_is_directory, entries) =
        collect_entries_with_policy(&base, &config.metadata_policy).await?;
    if receiver_is_directory != manifest.is_directory {
        return Ok(None);
    }
    let receiver_directory_metadata = if receiver_is_directory {
        let metadata = capture_directory_metadata_manifest(&base, &config.metadata_policy).await?;
        (!metadata.is_empty()).then_some(metadata)
    } else {
        None
    };
    let mut store = DeltaPlannerStore::new();
    let mut chunks_by_content = BTreeMap::new();
    let mut planner_chunks = Vec::new();
    let mut digests = Vec::with_capacity(entries.len());
    let mut read_buf = vec![0u8; config.chunk_size.max(1)];
    let mut receiver_metadata = BTreeMap::<String, EntryMetadata>::new();
    let mut stream_offset = 0u64;
    let mut index = 0u32;

    for entry in entries {
        let metadata = read_entry_metadata(&entry.abs_path, &config.metadata_policy).await?;
        if !metadata_is_content_delta_compatible(&metadata) {
            return Ok(None);
        }
        receiver_metadata.insert(entry.rel_path.clone(), metadata);
        let (size, content_id, content_sha256) =
            hash_file_streaming(&entry.abs_path, &mut read_buf).await?;
        digests.push(EntryDigest {
            rel_path: entry.rel_path.clone(),
            size,
            content_id,
            content_sha256,
        });
        let chunk_size = u64::try_from(delta_manifest.chunk_size.max(1)).unwrap_or(u64::MAX);
        let chunks = u64::try_from(planner_chunks.len()).unwrap_or(u64::MAX);
        if chunks.saturating_add(size.div_ceil(chunk_size)) > max_chunks {
            return Ok(None);
        }
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
    let metadata_matches_sender =
        receiver_metadata_matches_sender(&manifest.entries, &receiver_metadata)
            && receiver_directory_metadata_matches_sender(
                manifest.directory_metadata.as_ref(),
                receiver_directory_metadata.as_ref(),
            );
    Ok(Some(ReceiverDeltaBaseline {
        manifest: receiver_manifest,
        store,
        chunks_by_content,
        metadata_matches_sender,
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
        // A whole `chunk_size` chunk per iteration (asupersync-u4j7sr): one
        // read of `crate::fs::File` returns at most 128 KiB.
        let n = crate::net::atp::transport_common::delta::read_full_chunk(&mut file, &mut buf)
            .await
            .map_err(|err| TransportError::Source(format!("{}: {err}", path.display())))?;
        if n == 0 {
            break;
        }
        let bytes = &buf[..n];
        let size_bytes = u64::try_from(n)
            .map_err(|_| TransportError::Frame("delta chunk length overflow".to_string()))?;
        let content_id = ContentId::from_bytes(bytes);
        let content_id_hex = content_id.to_hex();
        // The planner needs verified hash/size coverage, while reconstruction
        // already owns one payload copy in chunks_by_content. Keeping another
        // Vec in DeltaPlannerStore duplicates baseline payload memory.
        store.insert_verified_coverage(content_id.clone(), size_bytes);
        chunks_by_content
            .entry(delta_content_key(content_id_hex.clone(), size_bytes))
            .or_insert_with(|| bytes.to_vec());
        planner_chunks.push(CasChunkRef {
            index: *next_index,
            byte_offset: *stream_offset,
            size_bytes,
            content_id,
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

/// Polls of a receipt send that keep the receive's cancellation masked.
///
/// A receipt is one Proof frame of at most [`MAX_FRAME_SIZE`] bytes plus an
/// empty Close frame, so a healthy send needs a handful of polls. Each frame's
/// send is also bounded in time by `idle_timeout`.
const RECEIPT_MASKED_POLLS: u32 = 1024;

/// How long a receipt send may continue once the receive has been asked to
/// stop. A peer that is reading gets its receipt within milliseconds. One that
/// is not must not hold the stop, and with it a server's drain (30 s by default
/// in atpd), for an `idle_timeout` per frame.
const RECEIPT_STOP_GRACE: Duration = Duration::from_secs(2);

/// Sends the receipt of a finished receive, then its Close frame.
///
/// By the time the receipt is sent, the receive has committed its files into
/// the destination (or found a verification failure and committed nothing). A
/// stop that arrives during the commit or the send must not make both peers
/// report a failed transfer whose files are already in place, so the send runs
/// with the receive's cancellation masked, for at most
/// [`RECEIPT_MASKED_POLLS`] polls and at most [`RECEIPT_STOP_GRACE`] after the
/// stop. A cancellation that arrived meanwhile is acknowledged once the receipt
/// is out. The receive has then finished its protocol, and a receive task
/// joined after [`TaskHandle::abort`](crate::runtime::TaskHandle::abort)
/// reports this outcome instead of a task-level cancellation. If the grace
/// runs out first, the receive ends with [`TransportError::Cancelled`].
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
    let mut send = std::pin::pin!(crate::combinator::try_commit_section(
        cx,
        RECEIPT_MASKED_POLLS,
        async {
            with_transport_timeout(
                cx,
                config.idle_timeout,
                "send proof",
                transport.send(&proof),
            )
            .await?;
            let close =
                Frame::empty(FrameType::Close).map_err(|e| TransportError::Frame(e.to_string()))?;
            let _ = with_transport_timeout(
                cx,
                config.idle_timeout,
                "send close",
                transport.send(&close),
            )
            .await;
            Ok::<(), TransportError>(())
        }
    ));
    // A mask-agnostic observer: the stop wakes it even while the masked write
    // is parked, and the first poll that sees the stop arms the grace.
    let mut stop = std::pin::pin!(cx.cancelled());
    let mut grace: Option<std::pin::Pin<Box<crate::time::Sleep>>> = None;
    let sent = std::future::poll_fn(|task| {
        if grace.is_none() && stop.as_mut().poll(task).is_ready() {
            grace = Some(Box::pin(crate::time::sleep(cx.now(), RECEIPT_STOP_GRACE)));
        }
        if let Some(timer) = grace.as_mut()
            && timer.as_mut().poll(task).is_ready()
        {
            return std::task::Poll::Ready(Err(TransportError::Cancelled));
        }
        send.as_mut().poll(task)
    })
    .await;
    if sent.is_ok() && cx.is_cancel_requested() {
        // The checkpoint's error is the acknowledgement itself: nothing is
        // left to stop.
        let _ = cx.checkpoint();
    }
    sent
}

async fn create_directory_metadata_paths(
    base: &Path,
    manifest: &TransferManifest,
) -> Result<(), TransportError> {
    let Some(directory_metadata) = &manifest.directory_metadata else {
        return Ok(());
    };

    reject_entry_destination_link_prefixes(base, base, None, false).await?;
    crate::fs::create_dir_all(base).await?;
    reject_entry_destination_link_prefixes(base, base, None, false).await?;

    let mut directories = directory_metadata.entries.iter().collect::<Vec<_>>();
    directories.sort_by(|left, right| {
        left.rel_path
            .split('/')
            .count()
            .cmp(&right.rel_path.split('/').count())
            .then_with(|| left.rel_path.cmp(&right.rel_path))
    });
    for directory in directories {
        let out_path = join_relative(base, &directory.rel_path)?;
        reject_entry_destination_link_prefixes(base, &out_path, None, false).await?;
        crate::fs::create_dir_all(&out_path).await?;
        reject_entry_destination_link_prefixes(base, &out_path, None, false).await?;
    }
    Ok(())
}

async fn apply_directory_metadata_best_effort(
    cx: &Cx,
    base: &Path,
    manifest: &TransferManifest,
) -> Result<(), TransportError> {
    let mut directories = BTreeMap::<&str, &EntryMetadata>::new();
    if let Some(directory_metadata) = &manifest.directory_metadata {
        for directory in &directory_metadata.entries {
            directories.insert(&directory.rel_path, &directory.metadata);
        }
    }
    // The validator keeps explicit and implicit directory paths disjoint; this
    // insertion remains a deterministic backstop for locally-built manifests.
    for entry in &manifest.entries {
        if let Some(metadata) = entry
            .metadata
            .as_ref()
            .filter(|metadata| matches!(metadata.file_kind, FileKind::Directory))
        {
            directories.insert(&entry.rel_path, metadata);
        }
    }

    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by(|(left_path, _), (right_path, _)| {
        right_path
            .split('/')
            .count()
            .cmp(&left_path.split('/').count())
            .then_with(|| left_path.cmp(right_path))
    });
    for (rel_path, metadata) in directories {
        let out_path = join_relative(base, rel_path)?;
        reject_entry_destination_link_prefixes(base, &out_path, None, false).await?;
        reject_non_directory_metadata_target(&out_path).await?;
        apply_entry_metadata_best_effort(cx, &out_path, metadata).await;
    }
    if let Some(root) = manifest
        .directory_metadata
        .as_ref()
        .and_then(|metadata| metadata.root.as_ref())
    {
        reject_entry_destination_link_prefixes(base, base, None, false).await?;
        reject_non_directory_metadata_target(base).await?;
        apply_entry_metadata_best_effort(cx, base, root).await;
    }
    Ok(())
}

async fn reject_non_directory_metadata_target(path: &Path) -> Result<(), TransportError> {
    let metadata = crate::fs::symlink_metadata(path).await?;
    if !metadata.is_dir() {
        return Err(TransportError::Source(format!(
            "directory metadata target is not a directory: {}",
            path.display()
        )));
    }
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
    reject_manifest_destination_link_prefixes(dest_dir, &base, manifest).await?;
    create_directory_metadata_paths(&base, manifest).await?;
    if manifest.is_directory && manifest.entries.is_empty() {
        reject_entry_destination_link_prefixes(&base, &base, None, false).await?;
        crate::fs::create_dir_all(&base).await?;
        reject_entry_destination_link_prefixes(&base, &base, None, false).await?;
        committed_paths.push(base.clone());
    }
    // Each committed file's directory is fsynced once, after the loop and
    // before the receipt, instead of after every rename (r02ssd).
    let mut parent_syncs = DeferredParentSyncs::default();
    // Plain regular files commit in batches, one blocking call each (dfdwyt).
    #[cfg(not(windows))]
    let mut regular_batch = Vec::new();
    for (entry, staging_path) in manifest.entries.iter().zip(staging_paths.iter()) {
        let out_path = if manifest.is_directory {
            join_relative(&base, &entry.rel_path)?
        } else {
            base.clone()
        };
        #[cfg(not(windows))]
        if is_plain_regular_entry(entry.metadata.as_ref()) {
            regular_batch.push(RegularCommit {
                out_path,
                staging_path: staging_path.clone(),
                metadata: entry.metadata.clone(),
            });
            if regular_batch.len() == REGULAR_COMMIT_BATCH {
                commit_regular_entries(
                    cx,
                    &base,
                    std::mem::take(&mut regular_batch),
                    &mut parent_syncs,
                    &mut committed_paths,
                )
                .await?;
            }
            continue;
        }
        // Any other entry may depend on an earlier one (a hardlink's primary),
        // so the files batched before it commit first.
        #[cfg(not(windows))]
        commit_regular_entries(
            cx,
            &base,
            std::mem::take(&mut regular_batch),
            &mut parent_syncs,
            &mut committed_paths,
        )
        .await?;
        reject_entry_destination_link_prefixes(
            &base,
            &out_path,
            entry
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.hardlink_target.as_deref()),
            entry
                .metadata
                .as_ref()
                .is_some_and(|metadata| matches!(metadata.file_kind, FileKind::Symlink)),
        )
        .await?;

        if let Some(meta) = &entry.metadata {
            if meta.file_kind.is_special() {
                #[cfg(unix)]
                if matches!(meta.file_kind, FileKind::Fifo) && config.allow_special_files {
                    if let Some(parent) = out_path.parent() {
                        crate::fs::create_dir_all(parent).await?;
                    }
                    reject_entry_destination_link_prefixes(&base, &out_path, None, false).await?;
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
        reject_entry_destination_link_prefixes(
            &base,
            &out_path,
            entry
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.hardlink_target.as_deref()),
            entry
                .metadata
                .as_ref()
                .is_some_and(|metadata| matches!(metadata.file_kind, FileKind::Symlink)),
        )
        .await?;

        if let Some(meta) = &entry.metadata {
            if matches!(meta.file_kind, FileKind::Directory) {
                crate::fs::create_dir_all(&out_path).await?;
                committed_paths.push(out_path);
                continue;
            }
        }

        if let Some(metadata) = entry
            .metadata
            .as_ref()
            .filter(|metadata| matches!(metadata.file_kind, FileKind::Symlink))
        {
            commit_symlink_transactionally(&entry.rel_path, &out_path, metadata).await?;
            committed_paths.push(out_path);
            continue;
        }

        let hardlink_target = entry
            .metadata
            .as_ref()
            .and_then(|m| m.hardlink_target.clone());
        if let Some(primary_rel) = hardlink_target {
            let primary_path = join_relative(&base, &primary_rel)?;
            commit_hardlink_transactionally(&primary_path, &out_path).await?;
            committed_paths.push(out_path);
            continue;
        }

        parent_syncs
            .commit_staged_regular_file(staging_path, &out_path)
            .await?;
        if let Some(meta) = &entry.metadata {
            apply_entry_metadata_best_effort(cx, &out_path, meta).await;
        }
        committed_paths.push(out_path);
    }
    #[cfg(not(windows))]
    commit_regular_entries(
        cx,
        &base,
        regular_batch,
        &mut parent_syncs,
        &mut committed_paths,
    )
    .await?;
    parent_syncs.sync().await?;
    mirror_committed_manifest(cx, dest_dir, manifest, config.mirror_policy).await?;
    apply_directory_metadata_best_effort(cx, &base, manifest).await?;
    Ok(committed_paths)
}

async fn mirror_committed_manifest(
    cx: &Cx,
    dest_dir: &Path,
    manifest: &TransferManifest,
    policy: MirrorPolicy,
) -> Result<(), TransportError> {
    if !manifest.is_directory {
        return Ok(());
    }
    if !policy.enabled {
        return Ok(());
    }

    let base = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
    let keep_rel_paths = manifest
        .entries
        .iter()
        .map(|entry| entry.rel_path.clone())
        .collect::<BTreeSet<_>>();
    mirror_dest(cx, &base, &keep_rel_paths, policy).await?;
    Ok(())
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
            let mut staged = create_owned_staging_file(&staging_path).await?;
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
                        write_sparse_zero_runs(&mut file, chunk).await?;
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
    trace_entry_metadata_result(cx, out_path, apply_entry_metadata(out_path, meta).await);
}

/// Traces what applying an entry's metadata skipped, or why it failed; a
/// failure never fails the commit.
fn trace_entry_metadata_result(
    cx: &Cx,
    out_path: &Path,
    applied: Result<MetadataApplyReport, StreamingError>,
) {
    match applied {
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
    on_progress: impl FnMut(u64, u64) + Send,
) -> Result<SendReport, TransportError> {
    send_path_with_options(
        cx,
        addr,
        source,
        config,
        peer_id,
        filter,
        SendOptions::new(),
        on_progress,
    )
    .await
}

/// Sender options beyond [`TransferConfig`], which is exhaustively
/// constructible and so cannot gain fields without breaking its callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SendOptions {
    /// Bulk-data compression (br-asupersync-t1fblr.16). The default,
    /// [`CompressionMode::Off`], sends exactly the frames older senders send.
    pub compression: CompressionMode,
    /// How many chunks of a file are compressed at once on the runtime's
    /// blocking pool (br-asupersync-t1fblr.25; at least 1, default
    /// [`codec::DEFAULT_COMPRESSION_PARALLELISM`]). It changes speed, never
    /// what [`CompressionMode::Zstd`] sends.
    pub compression_parallelism: usize,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl SendOptions {
    /// The default options: no compression.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            compression: CompressionMode::Off,
            compression_parallelism: codec::DEFAULT_COMPRESSION_PARALLELISM,
        }
    }

    /// These options with `compression`.
    #[must_use]
    pub const fn with_compression(mut self, compression: CompressionMode) -> Self {
        self.compression = compression;
        self
    }

    /// These options compressing up to `chunks` chunks at once (0 counts as
    /// 1).
    #[must_use]
    pub const fn with_compression_parallelism(mut self, chunks: usize) -> Self {
        self.compression_parallelism = chunks;
        self
    }
}

/// Files hashed by one blocking task of the sender's first pass, at most
/// (br-asupersync-dfdwyt).
const HASH_BATCH_FILES: usize = 64;

/// Bytes one first-pass hashing task reads, at most, plus one read. The
/// task stops there even inside a file, which the next task resumes, so a
/// dropped transfer stops reading within one task.
const HASH_BATCH_BYTES: u64 = 8 * 1024 * 1024;

/// Entries whose metadata one blocking task of the first pass reads.
const METADATA_BATCH_ENTRIES: usize = 1024;

/// The size, content id and SHA-256 of one entry's content.
type ContentDigest = (u64, ObjectId, [u8; 32]);

/// The primary entry of each hardlinked inode seen so far.
type HardlinkPrimaries = std::collections::HashMap<HardlinkIdentity, String>;

/// What one hashing task returns: the finished digests, the next content
/// job, and the file it stopped inside, if any.
type HashTaskOutcome = (
    Vec<(usize, ContentDigest)>,
    usize,
    Option<crate::net::atp::transport_common::streaming::SyncFileHash>,
);

/// Reads the policy-selected metadata of `entries` and detects hardlinks:
/// the first entry (by sorted path) for an inode is the primary that carries
/// the content, and later entries sharing it are sent content-free and
/// `hard_link`ed on the receiver. `primaries` carries over between calls.
/// Symlink metadata is validated as the receiver will.
fn capture_entry_metadata_sync(
    entries: &[(String, PathBuf)],
    policy: &MetadataPolicy,
    preserve_hardlinks: bool,
    primaries: &mut HardlinkPrimaries,
) -> Result<Vec<EntryMetadata>, TransportError> {
    use crate::net::atp::transport_common::metadata::{
        inode_key_if_regular_sync, read_entry_metadata_sync,
    };
    let mut metadatas = Vec::with_capacity(entries.len());
    for (rel_path, abs_path) in entries {
        let mut metadata = read_entry_metadata_sync(abs_path, policy)?;
        if preserve_hardlinks && matches!(metadata.file_kind, FileKind::Regular) {
            if let Some(key) = inode_key_if_regular_sync(abs_path)? {
                if let Some(primary) = primaries.get(&key) {
                    metadata.hardlink_target = Some(primary.clone());
                } else {
                    primaries.insert(key, rel_path.clone());
                }
            }
        }
        validate_symlink_metadata_for_receive(rel_path, &metadata).map_err(|error| {
            TransportError::Source(format!(
                "{}: invalid symlink metadata: {error}",
                abs_path.display()
            ))
        })?;
        metadatas.push(metadata);
    }
    Ok(metadatas)
}

/// The metadata half of the sender's first pass (br-asupersync-dfdwyt), in
/// blocking tasks of [`METADATA_BATCH_ENTRIES`] entries with a cancellation
/// checkpoint between them.
async fn capture_entry_metadata(
    cx: &Cx,
    entries: &[SourceEntry],
    config: &TransferConfig,
) -> Result<Vec<EntryMetadata>, TransportError> {
    let mut metadatas = Vec::with_capacity(entries.len());
    let mut primaries = HardlinkPrimaries::new();
    for batch in entries.chunks(METADATA_BATCH_ENTRIES) {
        cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
        let policy = config.metadata_policy.clone();
        let preserve_hardlinks = config.preserve_hardlinks;
        let paths: Vec<(String, PathBuf)> = batch
            .iter()
            .map(|entry| (entry.rel_path.clone(), entry.abs_path.clone()))
            .collect();
        let (result, carried) = crate::runtime::spawn_blocking(move || {
            let result =
                capture_entry_metadata_sync(&paths, &policy, preserve_hardlinks, &mut primaries);
            (result, primaries)
        })
        .await;
        primaries = carried;
        metadatas.extend(result?);
    }
    Ok(metadatas)
}

/// Paths the first pass opened, for tests that check which files it read.
#[cfg(test)]
static FIRST_PASS_OPENS: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

/// One blocking task of the sender's first pass (br-asupersync-dfdwyt).
///
/// It hashes the content `jobs` from `next` on, resuming `open` (a file an
/// earlier task stopped inside). It stops after [`HASH_BATCH_FILES`] files;
/// after [`HASH_BATCH_BYTES`] bytes, possibly inside a file, which it returns
/// open; or right after the file that takes `total` past `max`, so no later
/// file is opened.
fn hash_task(
    jobs: &[(usize, PathBuf)],
    mut next: usize,
    mut open: Option<crate::net::atp::transport_common::streaming::SyncFileHash>,
    buf: &mut [u8],
    mut total: u64,
    max: u64,
) -> Result<HashTaskOutcome, StreamingError> {
    use crate::net::atp::transport_common::streaming::SyncFileHash;

    let mut done = Vec::new();
    let mut read = 0u64;
    while let Some((index, path)) = jobs.get(next) {
        if done.len() >= HASH_BATCH_FILES || read >= HASH_BATCH_BYTES {
            break;
        }
        let mut file = match open.take() {
            Some(file) => file,
            None => {
                #[cfg(test)]
                {
                    if let Ok(mut opens) = FIRST_PASS_OPENS.lock() {
                        opens.push(path.clone());
                    }
                }
                SyncFileHash::open(path)?
            }
        };
        let n = file.read_some(path, buf)?;
        if n > 0 {
            read = read.saturating_add(n as u64);
            open = Some(file);
            continue;
        }
        let digest = file.finish();
        total = total.saturating_add(digest.0);
        done.push((*index, digest));
        next += 1;
        if total > max {
            break;
        }
    }
    Ok((done, next, open))
}

/// The content half of the sender's first pass (br-asupersync-dfdwyt): the
/// digest of every entry that carries content, `None` for the rest.
///
/// - Only regular files that are not hardlinks to a primary carry content,
///   so a FIFO is never opened (it would block the sender).
/// - Files are hashed in blocking tasks ([`hash_task`]) of at most
///   [`HASH_BATCH_FILES`] files or [`HASH_BATCH_BYTES`] bytes, with a
///   cancellation checkpoint between tasks.
/// - As before, the transfer is refused with `TooLarge`, carrying the total
///   through the end of the first file that takes it past
///   `max_transfer_bytes`, before any later file is opened.
///
/// `buf` (the send phase's read buffer) is the tasks' read buffer.
async fn hash_content_entries(
    cx: &Cx,
    entries: &[SourceEntry],
    metadatas: &[EntryMetadata],
    config: &TransferConfig,
    buf: &mut Vec<u8>,
) -> Result<Vec<Option<ContentDigest>>, TransportError> {
    let jobs: std::sync::Arc<Vec<(usize, PathBuf)>> = std::sync::Arc::new(
        entries
            .iter()
            .zip(metadatas)
            .enumerate()
            .filter(|(_, (_, metadata))| {
                matches!(metadata.file_kind, FileKind::Regular)
                    && metadata.hardlink_target.is_none()
            })
            .map(|(index, (entry, _))| (index, entry.abs_path.clone()))
            .collect(),
    );
    let mut hashed: Vec<Option<ContentDigest>> = std::iter::repeat_with(|| None)
        .take(entries.len())
        .collect();
    if jobs.is_empty() {
        return Ok(hashed);
    }
    // The opens below are std::fs on the blocking pool: check the same gate
    // crate::fs::File::open checks.
    crate::cx::io_gate::require_ambient_io("fs::File::open")
        .map_err(|error| TransportError::Source(format!("source hashing: {error}")))?;
    let max = config.max_transfer_bytes;
    let mut task_buf = std::mem::take(buf);
    if task_buf.is_empty() {
        task_buf = vec![0u8; config.chunk_size.max(1)];
    }
    let (mut total, mut next, mut open) = (0u64, 0usize, None);
    while next < jobs.len() {
        cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
        let task_jobs = std::sync::Arc::clone(&jobs);
        let mut moved_buf = std::mem::take(&mut task_buf);
        let moved_open = open.take();
        let (outcome, returned_buf) = crate::runtime::spawn_blocking(move || {
            let outcome = hash_task(&task_jobs, next, moved_open, &mut moved_buf, total, max);
            (outcome, moved_buf)
        })
        .await;
        task_buf = returned_buf;
        let (done, after, still_open) = outcome?;
        for (index, digest) in done {
            total = total.saturating_add(digest.0);
            if total > max {
                return Err(TransportError::TooLarge { size: total, max });
            }
            hashed[index] = Some(digest);
        }
        next = after;
        open = still_open;
    }
    *buf = task_buf;
    Ok(hashed)
}

/// Like [`send_path_filtered`], with [`SendOptions`].
///
/// With [`CompressionMode::Zstd`] (and the `zstd` cargo feature) the sender
/// offers zstd in its handshake. A receiver that accepts gets each chunk as
/// one zstd frame whenever that is smaller than the raw chunk; a receiver
/// that does not, including any receiver that predates compression, gets
/// every chunk raw. The manifest, the receiver's SHA-256 and merkle checks,
/// and the receipt always describe the raw bytes.
pub async fn send_path_with_options(
    cx: &Cx,
    addr: SocketAddr,
    source: &Path,
    config: TransferConfig,
    peer_id: &str,
    filter: &FilterSet,
    options: SendOptions,
    mut on_progress: impl FnMut(u64, u64) + Send,
) -> Result<SendReport, TransportError> {
    cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
    sender_validation::validate_config(&config)?;

    let (root_name, is_directory, mut entries) =
        collect_entries_with_policy(source, &config.metadata_policy).await?;
    if !filter.is_empty() {
        entries.retain(|entry| filter.is_path_included(&entry.rel_path));
    }
    let represented_directories =
        strict_ancestor_paths(entries.iter().map(|entry| entry.rel_path.as_str()));
    let directory_metadata = if is_directory {
        let mut directory_metadata =
            capture_directory_metadata_manifest(source, &config.metadata_policy).await?;
        directory_metadata
            .entries
            .retain(|directory| represented_directories.contains(&directory.rel_path));
        (!directory_metadata.is_empty()).then_some(directory_metadata)
    } else {
        None
    };

    // First pass (br-asupersync-dfdwyt). Every awaited file operation is a
    // blocking-pool handoff, and on a loaded host each one waits for a
    // scheduler wakeup: a small file used to cost about five here (metadata,
    // inode key, open, two reads). So metadata is read in blocking tasks of
    // many entries, as the QUIC sender's pass 1 does (br-asupersync-i7pdxb),
    // and content is hashed in blocking tasks of many files, each bounded in
    // bytes, with a cancellation checkpoint between tasks. `read_buf` is the
    // send phase's buffer and the hashing tasks'; peak memory stays one chunk
    // per side.
    let mut read_buf = vec![0u8; config.chunk_size.max(1)];
    let metadatas = capture_entry_metadata(cx, &entries, &config).await?;
    let hashed = hash_content_entries(cx, &entries, &metadatas, &config, &mut read_buf).await?;
    let mut digests: Vec<EntryDigest> = Vec::with_capacity(entries.len());
    let mut total_bytes: u64 = 0;
    for (entry, digest) in entries.iter().zip(hashed) {
        // Zero-content entries carry the canonical empty-content digest, which
        // the receiver, seeing no ObjectData frames for them, reconstructs.
        let (size, content_id, content_sha256) = digest.unwrap_or_else(|| {
            (
                0u64,
                ObjectId::content(ContentId::from_bytes(b"")),
                Sha256::digest(b"").into(),
            )
        });
        total_bytes = total_bytes.saturating_add(size);
        digests.push(EntryDigest {
            rel_path: entry.rel_path.clone(),
            size,
            content_id,
            content_sha256,
        });
    }

    let merkle_root_hex = flat_merkle_root_from_digests(&digests);
    let mut metadata_pairs: Vec<(&str, &EntryMetadata)> = digests
        .iter()
        .zip(&metadatas)
        .map(|(d, m)| (d.rel_path.as_str(), m))
        .collect();
    if let Some(directory_metadata) = &directory_metadata {
        metadata_pairs.extend(directory_metadata.commitment_pairs());
    }
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
            members: Vec::new(),
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
        directory_metadata,
        entries: manifest_entries,
        delta_manifest,
    };

    let stream =
        with_transport_timeout(cx, config.idle_timeout, "connect", TcpStream::connect(addr))
            .await?;
    let peer = stream.peer_addr().unwrap_or(addr);
    let mut transport = FrameTransport::new(stream);

    // Handshake. A compression offer rides in a frame-header extension, which
    // receivers that predate it never read.
    let mut hello = json_frame(
        FrameType::Handshake,
        &Hello {
            protocol: ATP_TCP_PROTOCOL,
            role: "sender".to_string(),
            peer_id: peer_id.to_string(),
        },
    )?;
    let offer = codec::local_offer(options.compression, config.chunk_size);
    transport.compression = options.compression;
    transport.compression_parallelism = options.compression_parallelism;
    if let Some(offer) = &offer {
        hello
            .header
            .extensions
            .insert(codec::CODEC_OFFER_EXTENSION, offer.to_bytes());
    }
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
    // Compress only after an accept that fits what this sender offered.
    transport.chunk_codec = offer.and_then(|offer| {
        ack_frame
            .header
            .extensions
            .get(&codec::CODEC_ACCEPT_EXTENSION)
            .and_then(|bytes| CodecAccept::from_bytes(bytes))
            .filter(|accept| offer.admits(accept))
    });

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
    sender_validation::validate_request(&manifest, &delta_request)?;

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

    sender_validation::validate_receipt(&manifest, bytes_sent, &receipt)?;

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

mod delta_manifest_validation;
mod sender_validation;

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
/// cooperative cleanup paths — for example when an outer race/select drops the
/// receive future directly or runtime teardown prevents another cooperative
/// poll. [`TaskHandle::abort`](crate::runtime::TaskHandle::abort) is not such a
/// hard drop: it requests cancellation and the scheduler repolls the task so it
/// can acknowledge cancellation and finish cleanup. The cooperative exits
/// remove the directory asynchronously and then [`StagingDirGuard::disarm`]
/// this guard, so the synchronous reclaim here only fires on an actual hard
/// future-drop. That is a rare, bounded best-effort cleanup (one
/// `remove_dir_all` on a small per-transfer scratch dir), not a hot path, so a
/// blocking host-boundary call in `Drop` is acceptable here.
struct StagingDirGuard {
    dir: PathBuf,
    armed: bool,
}

impl StagingDirGuard {
    fn new(dir: PathBuf) -> Self {
        Self { dir, armed: true }
    }

    fn create(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir(&dir)?;
        Ok(Self::new(dir))
    }

    fn path(&self) -> &Path {
        &self.dir
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

/// Owns a newly-created staging file while its blocking create operation is in
/// flight. If the awaiting receive future is dropped, the blocking result is
/// discarded and this guard closes and removes the file. Once delivered to the
/// receiver, ownership transfers to the enclosing [`StagingDirGuard`].
struct StagingFileGuard {
    path: PathBuf,
    file: Option<std::fs::File>,
    armed: bool,
}

impl StagingFileGuard {
    fn create(path: PathBuf) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Self {
            path,
            file: Some(file),
            armed: true,
        })
    }

    fn into_async_file(mut self) -> crate::fs::File {
        let file = self
            .file
            .take()
            .expect("armed staging file guard must own its file");
        self.armed = false;
        crate::fs::File::from_std(file)
    }

    /// Keeps the staging file, which the caller has already closed.
    fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for StagingFileGuard {
    fn drop(&mut self) {
        if self.armed {
            drop(self.file.take());
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

async fn create_owned_staging_file(path: &Path) -> Result<crate::fs::File, TransportError> {
    let path = path.to_owned();
    let guard = crate::runtime::spawn_blocking_io(move || StagingFileGuard::create(path)).await?;
    Ok(guard.into_async_file())
}

/// Creates the staging file at `path` holding `contents` in one blocking
/// call: the same create as [`create_owned_staging_file`], then the write and
/// the close, which were a blocking-pool handoff each (br-asupersync-dfdwyt).
/// A failed write removes the file, and so does dropping this future before
/// the call returns.
async fn write_whole_staging_file(path: &Path, contents: &[u8]) -> Result<(), TransportError> {
    use std::io::Write as _;

    let path = path.to_owned();
    let contents = contents.to_vec();
    let guard = crate::runtime::spawn_blocking_io(move || {
        let mut guard = StagingFileGuard::create(path)?;
        if let Some(mut file) = guard.file.take() {
            file.write_all(&contents)?;
        }
        Ok(guard)
    })
    .await?;
    guard.keep();
    Ok(())
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
    // No requested chunk is larger than this, so neither is a decompressed one.
    let largest_requested = request
        .missing_chunks
        .iter()
        .map(|chunk| chunk.size_bytes)
        .max()
        .unwrap_or(0);
    let mut raw_scratch = Vec::new();
    let recv_result: Result<(), TransportError> = async {
        loop {
            cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
            let frame =
                with_transport_timeout(cx, config.idle_timeout, "receive frame", transport.recv())
                    .await?;
            match frame.frame_type() {
                FrameType::ObjectData => {
                    let (entry_index, entry_offset, payload) = parse_data_frame(&frame)?;
                    let chunk = raw_chunk(
                        &frame,
                        transport.chunk_codec.as_ref(),
                        largest_requested,
                        payload,
                        &mut raw_scratch,
                    )?;
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

    let mut staging_guard = create_owned_staging_dir(dest_dir, &manifest.transfer_id).await?;
    let staging_dir = staging_guard.path().to_owned();

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
                let mut file = create_owned_staging_file(&staging_path).await?;
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
                drop(create_owned_staging_file(&staging_path).await?);
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
    let metadata_ok = transfer_manifest_metadata_commitment(manifest) == manifest.metadata_root_hex;

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
    match crate::fs::remove_dir_all(&staging_dir).await {
        Ok(()) => staging_guard.disarm(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => staging_guard.disarm(),
        Err(error) => return Err(TransportError::Io(error)),
    }

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
    receive_on_transport(
        cx,
        FrameTransport::new(stream),
        peer,
        dest_dir,
        config,
        peer_id,
    )
    .await
}

async fn receive_on_transport<S>(
    cx: &Cx,
    mut transport: FrameTransport<S>,
    peer: SocketAddr,
    dest_dir: &Path,
    config: TransferConfig,
    peer_id: &str,
) -> Result<ReceiveReport, TransportError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Reject invalid chunk geometry before the receiver starts accepting a
    // transfer or allocating its delta baseline scratch buffer.
    cx.checkpoint().map_err(|_| TransportError::Cancelled)?;
    sender_validation::validate_config(&config)?;

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
    let mut handshake_ack = json_frame(
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
    // Accept a compression offer this build can decode. Senders that predate
    // compression make no offer and get no accept, so they stay raw.
    if accepted {
        let accept = hello_frame
            .header
            .extensions
            .get(&codec::CODEC_OFFER_EXTENSION)
            .and_then(|bytes| CodecOffer::from_bytes(bytes))
            .and_then(|offer| codec::negotiate(&transport.decode, &offer));
        if let Some(accept) = accept {
            handshake_ack
                .header
                .extensions
                .insert(codec::CODEC_ACCEPT_EXTENSION, accept.to_bytes());
            transport.chunk_codec = Some(accept);
        }
    }
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
            let base = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
            reject_manifest_destination_link_prefixes(dest_dir, &base, &manifest).await?;
            create_directory_metadata_paths(&base, &manifest).await?;
            mirror_committed_manifest(cx, dest_dir, &manifest, config.mirror_policy).await?;
            apply_directory_metadata_best_effort(cx, &base, &manifest).await?;
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
    let mut staging_guard = create_owned_staging_dir(dest_dir, &manifest.transfer_id).await?;
    let staging_dir = staging_guard.path().to_owned();
    // Reclaim the staging dir even if this future is hard-dropped before
    // reaching a cooperative cleanup path. `TaskHandle::abort` ordinarily
    // requests cancellation and repolls the task; it does not hard-drop the
    // future. The cooperative exits below disarm this guard and remove the
    // directory asynchronously; only a true drop without another poll falls
    // back to the guard.
    let mut states: Vec<StagedEntryReceive> = manifest
        .entries
        .iter()
        .enumerate()
        .map(|(i, _)| StagedEntryReceive::new(staging_dir.join(i.to_string())))
        .collect();
    // The entry being received and its open staging file. The file is `None`
    // for an entry that arrived whole in one frame and is already written
    // and closed.
    let mut active: Option<(usize, Option<crate::fs::File>)> = None;
    let mut received: u64 = 0;
    // Holds one decompressed chunk at a time (at most MAX_COMPRESSED_CHUNK_RAW).
    let mut raw_scratch = Vec::new();

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
                    let (index, offset, payload) = parse_data_frame(&frame)?;
                    let idx = index as usize;
                    let entry = manifest.entries.get(idx).ok_or_else(|| {
                        TransportError::Frame(format!("ObjectData for unknown entry index {index}"))
                    })?;
                    // A compressed chunk may decode to at most what the entry
                    // still lacks; the checks below then run on raw bytes.
                    let remaining = entry
                        .size
                        .saturating_sub(states.get(idx).map_or(0, |st| st.bytes_written));
                    let chunk = raw_chunk(
                        &frame,
                        transport.chunk_codec.as_ref(),
                        remaining,
                        payload,
                        &mut raw_scratch,
                    )?;

                    // Close the previous entry's staging file when a new entry
                    // begins (the sender streams entries in index order).
                    let switch = matches!(&active, Some((cur, _)) if *cur != idx);
                    if switch {
                        if let Some((_, Some(mut file))) = active.take() {
                            file.flush().await?;
                        }
                    }
                    let mut whole_file = false;
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
                        // A file whose whole content is this frame is created,
                        // written and closed in one blocking call below.
                        whole_file = !config.sparse_files && chunk.len() as u64 == entry.size;
                        let file = if whole_file {
                            None
                        } else {
                            let file = create_owned_staging_file(&st.staging_path).await?;
                            // Pre-size a sparse file to the full length so holes
                            // (seeked-over zero runs) and a trailing hole are
                            // preserved without growing allocation.
                            if config.sparse_files {
                                file.set_len(entry.size).await?;
                            }
                            Some(file)
                        };
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
                    match file {
                        _ if whole_file => {
                            write_whole_staging_file(&states[idx].staging_path, chunk).await?;
                        }
                        Some(file) if config.sparse_files => {
                            write_sparse_zero_runs(file, chunk).await?;
                        }
                        Some(file) => file.write_all(chunk).await?,
                        // An entry that arrived whole already holds all its
                        // bytes; the size check above admits only an empty
                        // chunk, and any other would be lost, so refuse it.
                        None if chunk.is_empty() => {}
                        None => {
                            return Err(TransportError::Frame(format!(
                                "internal: entry {index} was already staged whole"
                            )));
                        }
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
        if let Some((_, Some(mut file))) = active.take() {
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
            if let Err(e) = create_owned_staging_file(&staging_path).await {
                let _ = crate::fs::remove_dir_all(&staging_dir).await;
                return Err(e);
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
    let metadata_ok =
        transfer_manifest_metadata_commitment(&manifest) == manifest.metadata_root_hex;

    let mut committed_paths: Vec<PathBuf> = Vec::new();
    let committed = sha_ok && merkle_ok && metadata_ok;
    if committed {
        // Commit by atomic rename from staging into the destination. The base
        // path is sanitized so a hostile `root_name` cannot escape `dest_dir`.
        let commit: Result<(), TransportError> = async {
            let base = safe_base_for_root_name(dest_dir, &manifest.root_name)?;
            reject_manifest_destination_link_prefixes(dest_dir, &base, &manifest).await?;
            create_directory_metadata_paths(&base, &manifest).await?;
            if manifest.is_directory && manifest.entries.is_empty() {
                reject_entry_destination_link_prefixes(&base, &base, None, false).await?;
                crate::fs::create_dir_all(&base).await?;
                reject_entry_destination_link_prefixes(&base, &base, None, false).await?;
                committed_paths.push(base.clone());
            }
            // Each committed file's directory is fsynced once, after the loop
            // and before the receipt, instead of after every rename (r02ssd).
            let mut parent_syncs = DeferredParentSyncs::default();
            // Plain regular files commit in batches, one blocking call each
            // (dfdwyt).
            #[cfg(not(windows))]
            let mut regular_batch = Vec::new();
            for (entry, staging_path) in manifest.entries.iter().zip(staging_paths.iter()) {
                let out_path = if manifest.is_directory {
                    join_relative(&base, &entry.rel_path)?
                } else {
                    base.clone()
                };
                #[cfg(not(windows))]
                if is_plain_regular_entry(entry.metadata.as_ref()) {
                    regular_batch.push(RegularCommit {
                        out_path,
                        staging_path: staging_path.clone(),
                        metadata: entry.metadata.clone(),
                    });
                    if regular_batch.len() == REGULAR_COMMIT_BATCH {
                        commit_regular_entries(
                            cx,
                            &base,
                            std::mem::take(&mut regular_batch),
                            &mut parent_syncs,
                            &mut committed_paths,
                        )
                        .await?;
                    }
                    continue;
                }
                // Any other entry may depend on an earlier one (a hardlink's
                // primary), so the files batched before it commit first.
                #[cfg(not(windows))]
                commit_regular_entries(
                    cx,
                    &base,
                    std::mem::take(&mut regular_batch),
                    &mut parent_syncs,
                    &mut committed_paths,
                )
                .await?;
                reject_entry_destination_link_prefixes(
                    &base,
                    &out_path,
                    entry
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata.hardlink_target.as_deref()),
                    entry
                        .metadata
                        .as_ref()
                        .is_some_and(|metadata| matches!(metadata.file_kind, FileKind::Symlink)),
                )
                .await?;

                // Special files (FIFO/socket/device). A FIFO is recreated via
                // `mkfifo` only when `allow_special_files` is set; everything else
                // (sockets, device nodes, or FIFOs without the opt-in) is skipped
                // and logged with no path committed, before any parent is made.
                if let Some(meta) = &entry.metadata {
                    if meta.file_kind.is_special() {
                        #[cfg(unix)]
                        if matches!(meta.file_kind, FileKind::Fifo) && config.allow_special_files {
                            if let Some(parent) = out_path.parent() {
                                crate::fs::create_dir_all(parent).await?;
                            }
                            reject_entry_destination_link_prefixes(&base, &out_path, None, false)
                                .await?;
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
                reject_entry_destination_link_prefixes(
                    &base,
                    &out_path,
                    entry
                        .metadata
                        .as_ref()
                        .and_then(|metadata| metadata.hardlink_target.as_deref()),
                    entry
                        .metadata
                        .as_ref()
                        .is_some_and(|metadata| matches!(metadata.file_kind, FileKind::Symlink)),
                )
                .await?;

                // An empty directory commits by creating the directory (with its
                // recorded mode) rather than renaming the (empty) staged file.
                if let Some(meta) = &entry.metadata {
                    if matches!(meta.file_kind, FileKind::Directory) {
                        crate::fs::create_dir_all(&out_path).await?;
                        committed_paths.push(out_path);
                        continue;
                    }
                }

                // A symlink commits by creating the link from its recorded target
                // rather than renaming the (empty) staged file into place.
                if let Some(metadata) = entry
                    .metadata
                    .as_ref()
                    .filter(|metadata| matches!(metadata.file_kind, FileKind::Symlink))
                {
                    commit_symlink_transactionally(&entry.rel_path, &out_path, metadata).await?;
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
                    commit_hardlink_transactionally(&primary_path, &out_path).await?;
                    committed_paths.push(out_path);
                    continue;
                }

                parent_syncs
                    .commit_staged_regular_file(staging_path, &out_path)
                    .await?;

                // Apply captured metadata (mode/mtime/owner) best-effort; skips
                // (e.g. chown without privilege) are traced, never fatal.
                if let Some(meta) = &entry.metadata {
                    apply_entry_metadata_best_effort(cx, &out_path, meta).await;
                }
                committed_paths.push(out_path);
            }
            #[cfg(not(windows))]
            commit_regular_entries(
                cx,
                &base,
                regular_batch,
                &mut parent_syncs,
                &mut committed_paths,
            )
            .await?;
            parent_syncs.sync().await?;
            mirror_committed_manifest(cx, dest_dir, &manifest, config.mirror_policy).await?;
            apply_directory_metadata_best_effort(cx, &base, &manifest).await?;
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
    match crate::fs::remove_dir_all(&staging_dir).await {
        Ok(()) => staging_guard.disarm(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => staging_guard.disarm(),
        Err(error) => return Err(TransportError::Io(error)),
    }

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
    send_receipt_and_close(cx, &mut transport, &config, &receipt).await?;

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
/// already set `root_name` to a bare file name (see `collect_entries`), so a
/// legitimate manifest is accepted unchanged while hostile or platform-
/// aliasing forms are rejected fail closed.
fn safe_base_for_root_name(dest_dir: &Path, root_name: &str) -> Result<PathBuf, TransportError> {
    validate_portable_path_component(root_name)
        .map_err(|_| TransportError::Source(format!("unsafe manifest root_name: {root_name}")))?;
    Ok(dest_dir.join(root_name))
}

fn join_relative(base: &Path, rel: &str) -> Result<PathBuf, TransportError> {
    validate_manifest_rel_path(rel)?;
    let mut out = base.to_path_buf();
    for component in rel.split('/') {
        out.push(component);
    }
    Ok(out)
}

async fn reject_existing_destination_ancestors(path: &Path) -> Result<(), TransportError> {
    for candidate in path.ancestors() {
        match path_is_link_or_reparse(candidate).await {
            Ok(true) => {
                return Err(TransportError::Source(format!(
                    "destination path crosses existing symlink or reparse point: {}",
                    candidate.display()
                )));
            }
            Ok(false) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(TransportError::Io(error)),
        }
    }
    Ok(())
}

async fn create_owned_staging_dir(
    dest_dir: &Path,
    transfer_id: &str,
) -> Result<StagingDirGuard, TransportError> {
    reject_existing_destination_ancestors(dest_dir).await?;
    crate::fs::create_dir_all(dest_dir).await?;
    reject_existing_destination_ancestors(dest_dir).await?;

    for _ in 0..32 {
        let sequence = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
        let nonce = OsEntropy.next_u64();
        let staging_dir = dest_dir.join(format!(
            ".atp-staging-{transfer_id}-{nonce:016x}-{sequence}"
        ));
        match crate::runtime::spawn_blocking_io(move || StagingDirGuard::create(staging_dir)).await
        {
            Ok(guard) => {
                reject_existing_destination_ancestors(guard.path()).await?;
                return Ok(guard);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(TransportError::Io(error)),
        }
    }
    Err(TransportError::Source(format!(
        "unable to create a unique owned staging directory under {}",
        dest_dir.display()
    )))
}

async fn reject_manifest_destination_link_prefixes(
    dest_dir: &Path,
    base: &Path,
    manifest: &TransferManifest,
) -> Result<(), TransportError> {
    reject_existing_link_or_reparse(dest_dir).await?;
    let mut verified = BTreeSet::new();
    for entry in &manifest.entries {
        let out_path = if manifest.is_directory {
            join_relative(base, &entry.rel_path)?
        } else {
            base.to_path_buf()
        };
        let replace_symlink_leaf = entry
            .metadata
            .as_ref()
            .is_some_and(|metadata| matches!(metadata.file_kind, FileKind::Symlink));
        reject_destination_link_prefix_cached(
            base,
            &out_path,
            &mut verified,
            !replace_symlink_leaf,
        )
        .await?;
    }
    if let Some(directory_metadata) = &manifest.directory_metadata {
        reject_destination_link_prefix_cached(base, base, &mut verified, true).await?;
        for directory in &directory_metadata.entries {
            let out_path = join_relative(base, &directory.rel_path)?;
            reject_destination_link_prefix_cached(base, &out_path, &mut verified, true).await?;
        }
    } else if manifest.entries.is_empty() {
        reject_destination_link_prefix_cached(base, base, &mut verified, true).await?;
    }
    Ok(())
}

async fn reject_entry_destination_link_prefixes(
    base: &Path,
    out_path: &Path,
    hardlink_target: Option<&str>,
    replace_symlink_leaf: bool,
) -> Result<(), TransportError> {
    let mut verified = BTreeSet::new();
    reject_destination_link_prefix_cached(base, out_path, &mut verified, !replace_symlink_leaf)
        .await?;
    if let Some(primary_rel) = hardlink_target {
        let primary_path = join_relative(base, primary_rel)?;
        reject_destination_link_prefix_cached(base, &primary_path, &mut verified, true).await?;
    }
    Ok(())
}

async fn reject_destination_link_prefix_cached(
    base: &Path,
    out_path: &Path,
    verified: &mut BTreeSet<PathBuf>,
    include_leaf: bool,
) -> Result<(), TransportError> {
    let (pending, unsafe_component) =
        collect_link_prefix_checks(base, out_path, verified, include_leaf)?;
    // The whole chain is checked in one blocking call, in the same order as
    // before. One call per component cost about 20 blocking-pool handoffs per
    // received file (br-asupersync-dfdwyt). The components before an unsafe
    // one are still checked first.
    if !pending.is_empty() {
        crate::runtime::spawn_blocking(move || check_link_prefixes_sync(&pending)).await?;
    }
    unsafe_component.map_or(Ok(()), Err)
}

fn check_link_prefixes_sync(paths: &[PathBuf]) -> Result<(), TransportError> {
    paths
        .iter()
        .try_for_each(|path| reject_existing_link_or_reparse_sync(path))
}

/// The paths `reject_destination_link_prefix_cached` checks, in order, each
/// added to `verified`, plus the error for a component that is not a plain
/// name, which is raised only after those checks pass.
fn collect_link_prefix_checks(
    base: &Path,
    out_path: &Path,
    verified: &mut BTreeSet<PathBuf>,
    include_leaf: bool,
) -> Result<(Vec<PathBuf>, Option<TransportError>), TransportError> {
    let rel = out_path.strip_prefix(base).map_err(|_| {
        TransportError::Source(format!(
            "destination path {} is outside safe base {}",
            out_path.display(),
            base.display()
        ))
    })?;

    // `base` is nested below dest_dir. A local process can replace that outer
    // directory with a junction after manifest preflight; checking only base
    // would then follow the substituted ancestor and see an apparently normal
    // tree. Per-entry guards use a fresh cache, so this revalidates the complete
    // outer chain immediately before each mutation.
    let mut pending = Vec::new();
    for ancestor in base
        .ancestors()
        .skip(1)
        .filter(|path| !path.as_os_str().is_empty())
    {
        if verified.insert(ancestor.to_path_buf()) {
            pending.push(ancestor.to_path_buf());
        }
    }

    let components = rel.components().collect::<Vec<_>>();
    let mut current = base.to_path_buf();
    if (include_leaf || !components.is_empty()) && verified.insert(current.clone()) {
        pending.push(current.clone());
    }
    let component_count = components.len();
    let mut unsafe_component = None;
    for (index, component) in components.into_iter().enumerate() {
        let Component::Normal(component) = component else {
            unsafe_component = Some(TransportError::Source(format!(
                "unsafe destination component in {}",
                out_path.display()
            )));
            break;
        };
        current.push(component);
        if (include_leaf || index + 1 < component_count) && verified.insert(current.clone()) {
            pending.push(current.clone());
        }
    }
    Ok((pending, unsafe_component))
}

/// [`reject_entry_destination_link_prefixes`] for a plain regular file (no
/// hardlink, not a symlink leaf), for a caller already on a blocking thread:
/// a fresh cache and the same checks in the same order.
#[cfg(not(windows))]
fn reject_regular_destination_link_prefixes_sync(
    base: &Path,
    out_path: &Path,
) -> Result<(), TransportError> {
    let mut verified = BTreeSet::new();
    let (pending, unsafe_component) =
        collect_link_prefix_checks(base, out_path, &mut verified, true)?;
    check_link_prefixes_sync(&pending)?;
    unsafe_component.map_or(Ok(()), Err)
}

/// Plain regular files committed per blocking call (br-asupersync-dfdwyt).
#[cfg(not(windows))]
const REGULAR_COMMIT_BATCH: usize = 64;

/// A plain regular entry waiting to commit with the others of its batch.
#[cfg(not(windows))]
struct RegularCommit {
    out_path: PathBuf,
    staging_path: PathBuf,
    metadata: Option<EntryMetadata>,
}

/// One regular file's commit on a blocking thread: the destination's
/// link-prefix walk, creating its parent, the walk again, the staged
/// install, then the captured metadata. That is the order the general
/// commit path runs them in. The metadata result is returned so the caller
/// traces it; a metadata failure never fails the commit.
#[cfg(not(windows))]
fn commit_regular_entry_sync(
    base: &Path,
    file: &RegularCommit,
) -> Result<Option<Result<MetadataApplyReport, StreamingError>>, TransportError> {
    reject_regular_destination_link_prefixes_sync(base, &file.out_path)?;
    if let Some(parent) = file.out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    reject_regular_destination_link_prefixes_sync(base, &file.out_path)?;
    install_staged_regular_file_sync(&file.staging_path, &file.out_path)?;
    Ok(file
        .metadata
        .as_ref()
        .map(|meta| apply_entry_metadata_sync(&file.out_path, meta)))
}

/// Commits a run of plain regular files in one blocking call
/// (br-asupersync-dfdwyt). Each file was one call of its own, after eight
/// separate handoffs per file before that. The files commit in order, and
/// the first failure stops the run: the files before it stay committed, are
/// recorded for the deferred parent sync and pushed to `committed_paths`,
/// exactly as one-by-one commits leave them, and the error is returned. A
/// receive dropped while the call runs lets the rest of its run commit.
#[cfg(not(windows))]
async fn commit_regular_entries(
    cx: &Cx,
    base: &Path,
    files: Vec<RegularCommit>,
    parent_syncs: &mut DeferredParentSyncs,
    committed_paths: &mut Vec<PathBuf>,
) -> Result<(), TransportError> {
    if files.is_empty() {
        return Ok(());
    }
    let base_path = base.to_path_buf();
    let (committed, failure) = crate::runtime::spawn_blocking(move || {
        let mut committed = Vec::with_capacity(files.len());
        for file in files {
            match commit_regular_entry_sync(&base_path, &file) {
                Ok(applied) => committed.push((file.out_path, applied)),
                Err(error) => return (committed, Some(error)),
            }
        }
        (committed, None)
    })
    .await;
    for (out_path, applied) in committed {
        parent_syncs.record(&out_path);
        if let Some(applied) = applied {
            trace_entry_metadata_result(cx, &out_path, applied);
        }
        committed_paths.push(out_path);
    }
    failure.map_or(Ok(()), Err)
}

/// One regular file through [`commit_regular_entries`].
#[cfg(all(test, not(windows)))]
async fn commit_regular_entry(
    cx: &Cx,
    base: &Path,
    out_path: &Path,
    staging_path: &Path,
    metadata: Option<&EntryMetadata>,
    parent_syncs: &mut DeferredParentSyncs,
) -> Result<(), TransportError> {
    let file = RegularCommit {
        out_path: out_path.to_path_buf(),
        staging_path: staging_path.to_path_buf(),
        metadata: metadata.cloned(),
    };
    commit_regular_entries(cx, base, vec![file], parent_syncs, &mut Vec::new()).await
}

/// Whether `metadata` describes a plain regular file, the entries
/// [`commit_regular_entries`] commits: not special, not a directory or a
/// symlink, and not a hardlink to an earlier entry.
#[cfg(not(windows))]
fn is_plain_regular_entry(metadata: Option<&EntryMetadata>) -> bool {
    metadata.is_none_or(|metadata| {
        matches!(metadata.file_kind, FileKind::Regular) && metadata.hardlink_target.is_none()
    })
}

async fn reject_existing_link_or_reparse(path: &Path) -> Result<(), TransportError> {
    let path = path.to_path_buf();
    crate::runtime::spawn_blocking(move || reject_existing_link_or_reparse_sync(&path)).await
}

fn reject_existing_link_or_reparse_sync(path: &Path) -> Result<(), TransportError> {
    match path_is_link_or_reparse_sync(path) {
        Ok(true) => Err(TransportError::Source(format!(
            "destination path crosses existing symlink or reparse point: {}",
            path.display()
        ))),
        Ok(false) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(TransportError::Io(error)),
    }
}

/// Run a persistent accept loop, handling each connection as a receive. Returns
/// when the capability context is cancelled. Connection-level errors are
/// reported via `on_result` and do not stop the loop.
///
/// A finished receive is reported within about 100 ms, without waiting for
/// another client to connect.
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
            // A child can finish immediately after the drain above. Poll the
            // capacity slot promptly instead of sleeping for the full accept
            // timeout (normally 60s), which would stall a queued fallback or
            // sequential client even though no transfer remains active.
            crate::time::sleep(cx.now(), accept_wait.min(Duration::from_millis(25))).await;
            continue;
        }
        // Finished receives are reported only by the drain above, which runs
        // between accepts. While a receive is in flight, bound the accept wait
        // so its result reaches `on_result` promptly instead of after the full
        // accept timeout (normally 60s) or the next client's connection. An
        // idle loop keeps the full wait as its cancellation checkpoint cadence.
        let wait = if active.is_empty() {
            accept_wait
        } else {
            accept_wait.min(Duration::from_millis(100))
        };
        let accept = with_transport_timeout(cx, wait, "accept", listener.accept()).await;
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
            Err(_) if cx.is_cancel_requested() => {
                // Cancellation interrupts the pending accept. That is shutdown,
                // not an accept failure: the check at the top of the loop
                // drains the receive tasks and returns without reporting it.
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
#[path = "mod_inline_tests.rs"]
mod tests;
