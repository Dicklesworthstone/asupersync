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
/// returns the byte count (`0` only at EOF).
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
    let mut filled = 0usize;
    while filled < buf.len() {
        let read = reader.read(&mut buf[filled..]).await?;
        if read == 0 {
            break;
        }
        filled += read;
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
/// chunk and the shifted tail keeps its content ids. Wired into the delta
/// manifest builders in a later sizeku slice; landed as a standalone, unit-tested
/// primitive first.
#[allow(dead_code)] // wired into the delta manifest builders in a later sizeku slice
pub(crate) mod cdc {
    /// Minimum content-defined chunk size.
    pub(crate) const MIN_CHUNK_BYTES: usize = 16 * 1024;
    /// Target average content-defined chunk size (tracks the mask bits).
    pub(crate) const AVG_CHUNK_BYTES: usize = 32 * 1024;
    /// Maximum content-defined chunk size (hard cut).
    pub(crate) const MAX_CHUNK_BYTES: usize = 64 * 1024;

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
    pub(crate) fn chunk_spans(bytes: &[u8]) -> Vec<(usize, usize)> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Serves at most `cap` bytes per poll, like `crate::fs::File` does since
    /// its poll path hops to the blocking pool in bounded pieces.
    struct ShortReader {
        data: Vec<u8>,
        pos: usize,
        cap: usize,
    }

    impl crate::io::AsyncRead for ShortReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut crate::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let n = buf
                .remaining()
                .min(this.cap)
                .min(this.data.len() - this.pos);
            buf.put_slice(&this.data[this.pos..this.pos + n]);
            this.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    /// asupersync-u4j7sr: a chunk is the whole buffer (or the tail at EOF),
    /// not whatever one bounded read happened to return.
    #[test]
    fn read_full_chunk_fills_the_buffer_across_short_reads() {
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let mut reader = ShortReader {
            data: data.clone(),
            pos: 0,
            cap: 128 * 1024,
        };
        let mut buf = vec![0u8; 256 * 1024];

        let first = futures_lite::future::block_on(read_full_chunk(&mut reader, &mut buf)).unwrap();
        assert_eq!(first, buf.len(), "one 128 KiB read is not a chunk");
        assert_eq!(&buf[..first], &data[..first]);

        let second =
            futures_lite::future::block_on(read_full_chunk(&mut reader, &mut buf)).unwrap();
        assert_eq!(
            second,
            data.len() - 256 * 1024,
            "the final chunk is the tail"
        );
        assert_eq!(&buf[..second], &data[256 * 1024..]);

        let eof = futures_lite::future::block_on(read_full_chunk(&mut reader, &mut buf)).unwrap();
        assert_eq!(eof, 0);
    }

    fn assert_legacy_request_fixture(fixture: Value, expected_mode: DeltaWireMode) {
        let decoded: DeltaObjectRequest =
            serde_json::from_value(fixture.clone()).expect("decode legacy delta request fixture");
        assert_eq!(decoded.mode, expected_mode);
        assert_eq!(
            serde_json::to_value(decoded).expect("encode legacy delta request fixture"),
            fixture
        );
    }

    #[test]
    fn legacy_delta_object_request_json_schema_is_stable() {
        assert_legacy_request_fixture(
            json!({
                "mode": "full_object",
                "fallback_reason": "receiver_delta_state_unavailable",
                "sender_merkle_root_hex": "11".repeat(32),
                "receiver_merkle_root_hex": "22".repeat(32),
                "missing_bytes": 0,
                "shared_chunks": 0,
                "stale_chunks": 0,
                "missing_chunks": []
            }),
            DeltaWireMode::FullObject,
        );
        assert_legacy_request_fixture(
            json!({
                "mode": "delta_chunks",
                "sender_merkle_root_hex": "33".repeat(32),
                "receiver_merkle_root_hex": "44".repeat(32),
                "missing_bytes": 7,
                "shared_chunks": 3,
                "stale_chunks": 1,
                "missing_chunks": [{
                    "index": 4,
                    "entry_index": 2,
                    "rel_path": "tree/leaf.bin",
                    "entry_offset": 9,
                    "stream_offset": 15,
                    "size_bytes": 7,
                    "content_id_hex": "55".repeat(32)
                }]
            }),
            DeltaWireMode::DeltaChunks,
        );
        assert_legacy_request_fixture(
            json!({
                "mode": "already_in_sync",
                "sender_merkle_root_hex": "66".repeat(32),
                "missing_bytes": 0,
                "shared_chunks": 9,
                "stale_chunks": 0,
                "missing_chunks": []
            }),
            DeltaWireMode::AlreadyInSync,
        );
    }

    #[test]
    fn legacy_delta_manifest_json_schema_is_stable() {
        let fixture = json!({
            "schema": "asupersync.atp.tcp.delta-chunk-manifest.v1",
            "tree_id": "tree-a",
            "chunk_size": 65536,
            "total_size_bytes": 7,
            "merkle_root_hex": "77".repeat(32),
            "chunks": [{
                "index": 4,
                "entry_index": 2,
                "rel_path": "tree/leaf.bin",
                "entry_offset": 9,
                "stream_offset": 15,
                "size_bytes": 7,
                "content_id_hex": "88".repeat(32)
            }]
        });
        let decoded: DeltaManifestWire =
            serde_json::from_value(fixture.clone()).expect("decode legacy delta manifest fixture");

        assert_eq!(
            serde_json::to_value(decoded).expect("encode legacy delta manifest fixture"),
            fixture
        );
    }

    // --- br-asupersync-sizeku: content-defined delta chunker (cdc) ---

    fn cdc_fixture(len: usize, seed: u32) -> Vec<u8> {
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

    fn cdc_chunks(data: &[u8]) -> Vec<Vec<u8>> {
        cdc::chunk_spans(data)
            .into_iter()
            .map(|(offset, len)| data[offset..offset + len].to_vec())
            .collect()
    }

    #[test]
    fn cdc_spans_tile_the_input_and_stay_in_bounds() {
        let data = cdc_fixture(512 * 1024, 0x5eed);
        let chunks = cdc_chunks(&data);
        assert_eq!(chunks.concat(), data, "spans must exactly tile the input");
        assert!(chunks.len() > 2, "256KiB fixed chunks would give only two");
        let nonfinal = chunks.len().saturating_sub(1);
        assert!(
            chunks
                .iter()
                .take(nonfinal)
                .all(|c| c.len() >= cdc::MIN_CHUNK_BYTES && c.len() <= cdc::MAX_CHUNK_BYTES),
            "every non-final chunk must be within [MIN, MAX]"
        );
        assert!(
            chunks.iter().any(|c| c.len() < cdc::MAX_CHUNK_BYTES),
            "gear hash should find a content boundary before the hard cap"
        );
    }

    #[test]
    fn cdc_resynchronizes_after_insert() {
        // The insert win: an inserted region costs ~one new chunk; the shifted
        // tail re-synchronizes and keeps its content (fixed-size chunking would
        // change every later chunk).
        let mut data = cdc_fixture(768 * 1024, 0xfeed);
        let original = cdc_chunks(&data);
        data.splice(96 * 1024..96 * 1024, [0xA5; 257]);
        let shifted = cdc_chunks(&data);

        let original_set: std::collections::BTreeSet<Vec<u8>> = original.iter().cloned().collect();
        let shared = shifted.iter().filter(|c| original_set.contains(*c)).count();
        assert!(
            shared * 2 >= original.len(),
            "CDC must resync after a small insert (shared={shared}, original={})",
            original.len()
        );
    }

    #[test]
    fn cdc_localizes_a_same_length_edit() {
        let original_data = cdc_fixture(2 * 1024 * 1024, 0xabcd);
        let mut edited_data = original_data.clone();
        let (edit_start, edit_len) = (1024 * 1024, 100 * 1024);
        for (offset, byte) in edited_data[edit_start..edit_start + edit_len]
            .iter_mut()
            .enumerate()
        {
            *byte = ((offset * 73 + 19) % 251) as u8;
        }
        let original_set: std::collections::BTreeSet<Vec<u8>> =
            cdc_chunks(&original_data).into_iter().collect();
        let missing_bytes: usize = cdc_chunks(&edited_data)
            .into_iter()
            .filter(|c| !original_set.contains(c))
            .map(|c| c.len())
            .sum();
        assert!(
            missing_bytes <= 192 * 1024,
            "a 100KiB same-length edit dirtied {missing_bytes} bytes of chunks"
        );
    }

    #[test]
    fn cdc_empty_input_yields_no_spans() {
        assert!(cdc::chunk_spans(&[]).is_empty());
    }
}
