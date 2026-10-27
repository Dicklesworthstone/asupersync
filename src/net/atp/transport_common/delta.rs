//! Shared wire types for receiver-driven ATP delta negotiation.
//!
//! The sender advertises a bounded chunk manifest in `ObjectManifest`; the
//! receiver answers with an `ObjectRequest` selecting a full transfer, an
//! explicit missing-chunk set, or a live already-in-sync receipt path. Keeping
//! these types transport-neutral lets TCP, authenticated QUIC, and protected RQ
//! use one fail-closed control schema. These data-transfer objects do not
//! authenticate themselves: each transport must bind them to its current
//! session, transfer, destination, and terminal committed receipt.

use serde::{Deserialize, Serialize};

/// Canonical schema tag for ATP's receiver-driven delta chunk manifest.
pub const ATP_DELTA_CHUNK_MANIFEST_SCHEMA: &str = "asupersync.atp.tcp.delta-chunk-manifest.v1";

/// Sender-side chunk manifest used by receiver-driven delta planning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// Hex-encoded domain-separated content id for the chunk bytes.
    pub content_id_hex: String,
}

/// Receiver-selected wire mode for one delta-capable object request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeltaWireMode {
    /// Send every object byte through the transport's ordinary full path.
    FullObject,
    /// Send only the receiver-selected missing chunks.
    DeltaChunks,
    /// Send no object bytes, but still require a live committed receipt.
    AlreadyInSync,
}

/// Receiver response to a sender's delta-capable object manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeltaObjectRequest {
    pub(crate) mode: DeltaWireMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fallback_reason: Option<String>,
    pub(crate) sender_merkle_root_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) receiver_merkle_root_hex: Option<String>,
    pub(crate) missing_bytes: u64,
    pub(crate) shared_chunks: u64,
    pub(crate) stale_chunks: u64,
    pub(crate) missing_chunks: Vec<DeltaChunkWire>,
}

impl DeltaObjectRequest {
    pub(crate) fn full(
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

/// Fills `buf` from `reader` until it is full or the reader reports EOF and
/// returns the byte count. An empty buffer returns `0` without polling the
/// reader; otherwise `0` means EOF.
///
/// Interrupted reads are retried without losing the completed prefix unless
/// the current context's checkpoint acknowledges cancellation; in that case
/// the original interruption is returned. After 64 read attempts, including
/// interruptions, the future yields before doing more work. A yield never
/// becomes a short chunk: only EOF ends a partial chunk. This does not preempt
/// a syscall or register a cancellation observer for a parked reader. Dropping
/// the wait can consume a prefix; callers must not restart it as though the
/// reader had not advanced.
///
/// One `AsyncReadExt::read` is not one chunk: `crate::fs::File`'s poll path
/// hops to the blocking pool in bounded pieces (128 KiB), so a chunk builder
/// that treated a single read as a `chunk_size` chunk produced 128 KiB chunks
/// for every larger file and the peer's fixed-size chunk validator rejected
/// the manifest as "malformed ... delta chunk at position 0"
/// (asupersync-u4j7sr). Every delta chunk builder reads through this helper.
pub async fn read_full_chunk<R>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize>
where
    R: crate::io::AsyncRead + Unpin,
{
    use crate::io::AsyncReadExt as _;
    const READ_ATTEMPTS_PER_TURN: usize = 64;

    let mut filled = 0usize;
    let mut attempts = 0usize;
    while filled < buf.len() {
        if attempts == READ_ATTEMPTS_PER_TURN {
            crate::runtime::yield_now().await;
            attempts = 0;
        }
        attempts += 1;
        match reader.read(&mut buf[filled..]).await {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                // Async adapters also use Interrupted for cancellation. Do
                // not turn their terminal cancellation into an EINTR loop.
                // checkpoint, rather than is_cancel_requested, honors masks.
                if crate::cx::Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Content-defined (FastCDC) chunking for delta-object manifests
/// (br-asupersync-sizeku).
///
/// Ported from the proven CLI chunker (`src/bin/atp.rs`, br-asupersync-iz269u)
/// into the library so both transport delta builders (RQ + TCP) can produce
/// content-defined boundaries instead of fixed-size chunks. Fixed-size chunking
/// re-chunks every byte after an insertion, so all later content ids change and
/// the inserted region gets no delta reuse; content-defined boundaries
/// re-synchronize a few tens of bytes past an edit, so an insert costs ~one new
/// chunk and the shifted tail keeps its content ids. RQ opts into these
/// boundaries only after authenticating both peers' CDC capabilities; fixed
/// manifests keep their existing wire meaning.
pub(crate) mod cdc {
    /// This schema is emitted only after an authenticated CDC capability
    /// exchange. The existing fixed-chunk schema keeps its original meaning.
    pub const MANIFEST_SCHEMA: &str = "asupersync.atp.rq.cdc-chunk-manifest.v1";

    /// Minimum content-defined chunk size.
    pub const MIN_CHUNK_BYTES: usize = 16 * 1024;
    /// Target average content-defined chunk size (tracks the mask bits).
    pub const AVG_CHUNK_BYTES: usize = 32 * 1024;
    /// Maximum content-defined chunk size (hard cut).
    pub const MAX_CHUNK_BYTES: usize = 64 * 1024;

    /// Gear boundary mask: `log2(AVG)=15` bits in the TOP of the hash. The
    /// gear's low bits carry only the last few bytes (and freeze on runs of
    /// equal bytes) while the high bits accumulate ~64 bytes through the
    /// shift-add carries; masking the top bits finds boundaries on structured
    /// data where a low-bit mask degenerates to max-cap-only chunks
    /// (br-asupersync-iz269u).
    const BOUNDARY_MASK_BITS: u32 = 15;
    const BOUNDARY_MASK: u64 =
        ((1u64 << BOUNDARY_MASK_BITS) - 1) << (64 - BOUNDARY_MASK_BITS);
    const _: () = assert!(
        AVG_CHUNK_BYTES == 1usize << BOUNDARY_MASK_BITS,
        "boundary mask bits must track the average chunk size",
    );

    /// FastCDC-style gear hash: `hash = (hash << 1) + T[byte]`. No explicit
    /// window: the shift ages old bytes out of the masked top bits and the
    /// add's carry mixes across bit positions. The rolling state is continuous
    /// across chunk boundaries by design — content-defined resync depends only
    /// on the last ~64 bytes, so the hash re-aligns a few tens of bytes past an
    /// edit (a per-chunk reset would defeat resynchronization).
    #[derive(Debug)]
    struct Gear {
        hash: u64,
    }

    impl Gear {
        fn new() -> Self {
            Self { hash: 0 }
        }
        fn update(&mut self, byte: u8) {
            self.hash = (self.hash << 1).wrapping_add(gear_value(byte));
        }
        fn hash(&self) -> u64 {
            self.hash
        }
    }

    const fn gear_value(byte: u8) -> u64 {
        splitmix64((byte as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))
    }

    const fn splitmix64(mut value: u64) -> u64 {
        value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut mixed = value;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^ (mixed >> 31)
    }

    /// Content-defined chunk boundaries over `bytes`, returned as `(offset,
    /// len)` spans that exactly tile `[0, bytes.len())` in order. A
    /// sub-minimum final span is merged into the previous span when that keeps
    /// it within the max, so every span except possibly a lone final one is in
    /// `MIN_CHUNK_BYTES..=MAX_CHUNK_BYTES`. Deterministic: identical bytes
    /// always yield identical spans, so a sender and receiver chunking an
    /// identical file agree on boundaries (and thus content ids) with no shared
    /// state.
    #[cfg(test)]
    pub fn chunk_spans(bytes: &[u8]) -> Vec<(usize, usize)> {
        let mut spans: Vec<(usize, usize)> = Vec::new();
        if bytes.is_empty() {
            return spans;
        }
        let mut gear = Gear::new();
        let mut chunk_start = 0usize;
        for (index, &byte) in bytes.iter().enumerate() {
            gear.update(byte);
            let end = index + 1;
            let chunk_len = end - chunk_start;
            if chunk_len < MIN_CHUNK_BYTES {
                continue;
            }
            if chunk_len >= MAX_CHUNK_BYTES || (gear.hash() & BOUNDARY_MASK) == 0 {
                spans.push((chunk_start, chunk_len));
                chunk_start = end;
            }
        }
        if chunk_start < bytes.len() {
            let tail_len = bytes.len() - chunk_start;
            let merge = spans.last().is_some_and(|&(_, prev_len)| {
                tail_len < MIN_CHUNK_BYTES && prev_len + tail_len <= MAX_CHUNK_BYTES
            });
            if merge {
                if let Some(last) = spans.last_mut() {
                    last.1 += tail_len;
                }
            } else {
                spans.push((chunk_start, tail_len));
            }
        }
        spans
    }

    /// Streaming equivalent of `chunk_spans`, independent of read boundaries.
    ///
    /// A completed chunk is retained until the following boundary or EOF so
    /// the final short tail can be merged exactly as in `chunk_spans`. The
    /// reader retains at most three `MAX_CHUNK_BYTES` buffers, regardless of
    /// the input size. Dropping it abandons its consumed prefix; it must not
    /// be reconstructed over the already-advanced underlying reader.
    #[derive(Debug)]
    pub struct ChunkReader<R> {
        reader: R,
        gear: Gear,
        input: Vec<u8>,
        input_pos: usize,
        input_len: usize,
        pending: Vec<u8>,
        current: Vec<u8>,
        eof: bool,
    }

    impl<R: crate::io::AsyncRead + Unpin> ChunkReader<R> {
        pub fn new(reader: R) -> Self {
            Self {
                reader,
                gear: Gear::new(),
                input: vec![0; MAX_CHUNK_BYTES],
                input_pos: 0,
                input_len: 0,
                pending: Vec::new(),
                current: Vec::with_capacity(MAX_CHUNK_BYTES),
                eof: false,
            }
        }

        /// Returns the next complete content-defined chunk.
        ///
        /// If this future is dropped before completion, discard the reader:
        /// filling an input buffer may already have consumed a partial read.
        pub async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
            loop {
                if self.eof {
                    if !self.pending.is_empty() {
                        if self.current.len() < MIN_CHUNK_BYTES
                            && self.pending.len() + self.current.len() <= MAX_CHUNK_BYTES
                        {
                            self.pending.append(&mut self.current);
                        }
                        return Ok(Some(std::mem::take(&mut self.pending)));
                    }
                    return Ok((!self.current.is_empty())
                        .then(|| std::mem::take(&mut self.current)));
                }
                if self.input_pos == self.input_len {
                    self.input_len =
                        super::read_full_chunk(&mut self.reader, &mut self.input).await?;
                    self.input_pos = 0;
                    if self.input_len == 0 {
                        self.eof = true;
                        continue;
                    }
                }
                while self.input_pos < self.input_len {
                    let byte = self.input[self.input_pos];
                    self.input_pos += 1;
                    self.gear.update(byte);
                    self.current.push(byte);
                    let len = self.current.len();
                    if len >= MIN_CHUNK_BYTES
                        && (len == MAX_CHUNK_BYTES || self.gear.hash() & BOUNDARY_MASK == 0)
                    {
                        let complete = std::mem::replace(
                            &mut self.current,
                            Vec::with_capacity(MAX_CHUNK_BYTES),
                        );
                        let ready = std::mem::replace(&mut self.pending, complete);
                        if !ready.is_empty() {
                            return Ok(Some(ready));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "delta_inline_tests.rs"]
mod tests;
