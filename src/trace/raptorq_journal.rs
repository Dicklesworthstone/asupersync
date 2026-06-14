//! Crash-durable RaptorQ trace-journal frame format
//! (br-asupersync-raptorq-leverage-3bb2pl.2).
//!
//! # Why
//!
//! The deepest forensics irony is that the trace explaining a crash is the thing
//! most likely destroyed *by* the crash — partial writes, torn files, a lost ring
//! tail. Fountain-coding the trace stream means **any K of the N** written symbol
//! frames reconstructs the checkpoint, so partial loss becomes recoverable by
//! construction.
//!
//! This module is the foundation slice: the pure, allocation-light **on-disk
//! frame format** for striped symbol journals, plus integrity checks. It has no
//! scheduler, no I/O, and no dependency on the RaptorQ encoder or the trace ring
//! internals — the encode/recover pipeline (background blocking-pool symbol
//! encoding, striped writers across failure domains, and `frankenlab
//! trace-recover`) builds on top of this layout.
//!
//! # Frame layout
//!
//! Each frame is a fixed [`JOURNAL_FRAME_HEADER_LEN`]-byte header, the symbol
//! payload, and a trailing CRC-32 over the payload. All integers are big-endian.
//!
//! ```text
//! offset size field
//!      0    8  magic                = b"ASRQJRN1"
//!      8    2  version              = JOURNAL_FRAME_VERSION
//!     10    2  flags                (bit 0 = checkpoint/fsync boundary)
//!     12    8  epoch                (trace checkpoint epoch tag)
//!     20    4  source_block_number  (RaptorQ SBN)
//!     24    4  encoding_symbol_id   (RaptorQ ESI)
//!     28    4  source_symbol_count  (K' for the block)
//!     32    4  symbol_size          (T: payload bytes per symbol)
//!     36    4  payload_len          (actual payload bytes in this frame, <= T)
//!     40    4  header_crc           (CRC-32 over bytes 0..40)
//!     44    N  payload              (N = payload_len)
//!   44+N    4  payload_crc          (CRC-32 over the payload bytes)
//! ```
//!
//! A torn tail (a frame cut short mid-write) is detected as
//! [`JournalFrameError::Truncated`] by [`JournalFrame::decode`], and a flipped
//! bit is detected by the header or payload CRC — both let recovery skip a
//! damaged frame and keep decoding the surviving symbols.

use std::collections::{BTreeMap, BTreeSet};

/// Magic identifying a RaptorQ trace-journal frame.
pub const JOURNAL_FRAME_MAGIC: [u8; 8] = *b"ASRQJRN1";

/// Current frame format version.
pub const JOURNAL_FRAME_VERSION: u16 = 1;

/// Flag bit set on a frame that completes a checkpoint / fsync boundary.
pub const JOURNAL_FLAG_CHECKPOINT_BOUNDARY: u16 = 0b0000_0001;

/// Fixed header length, including the trailing `header_crc`.
pub const JOURNAL_FRAME_HEADER_LEN: usize = 44;

/// Length of a trailing CRC field.
const CRC_LEN: usize = 4;

/// Errors returned when decoding a journal frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalFrameError {
    /// The buffer is shorter than a complete header.
    Truncated,
    /// The leading magic bytes did not match [`JOURNAL_FRAME_MAGIC`].
    BadMagic,
    /// The frame version is newer than this reader understands.
    UnsupportedVersion(u16),
    /// `payload_len` would exceed the remaining buffer (a torn tail).
    PayloadTruncated,
    /// The header CRC did not match the header bytes.
    HeaderChecksumMismatch,
    /// The payload CRC did not match the payload bytes.
    PayloadChecksumMismatch,
}

impl core::fmt::Display for JournalFrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("journal frame truncated before a full header"),
            Self::BadMagic => f.write_str("journal frame magic mismatch"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported journal frame version {v}"),
            Self::PayloadTruncated => f.write_str("journal frame payload truncated (torn tail)"),
            Self::HeaderChecksumMismatch => f.write_str("journal frame header CRC mismatch"),
            Self::PayloadChecksumMismatch => f.write_str("journal frame payload CRC mismatch"),
        }
    }
}

impl std::error::Error for JournalFrameError {}

/// Decoded header of a single striped symbol frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalFrameHeader {
    /// Trace checkpoint epoch this frame belongs to.
    pub epoch: u64,
    /// RaptorQ source block number (SBN).
    pub source_block_number: u32,
    /// RaptorQ encoding symbol id (ESI) of this frame.
    pub encoding_symbol_id: u32,
    /// Number of source symbols (K') needed to decode the block.
    pub source_symbol_count: u32,
    /// Symbol size T in bytes (the per-symbol payload capacity).
    pub symbol_size: u32,
    /// Bytes of payload actually carried by this frame (`<= symbol_size`).
    pub payload_len: u32,
    /// Frame flags (see [`JOURNAL_FLAG_CHECKPOINT_BOUNDARY`]).
    pub flags: u16,
}

impl JournalFrameHeader {
    /// Whether this frame completes a checkpoint / fsync boundary.
    #[must_use]
    pub const fn is_checkpoint_boundary(&self) -> bool {
        self.flags & JOURNAL_FLAG_CHECKPOINT_BOUNDARY != 0
    }

    /// Serialize the header (including its trailing CRC) into a fixed buffer.
    #[must_use]
    fn encode(&self) -> [u8; JOURNAL_FRAME_HEADER_LEN] {
        let mut out = [0u8; JOURNAL_FRAME_HEADER_LEN];
        out[0..8].copy_from_slice(&JOURNAL_FRAME_MAGIC);
        out[8..10].copy_from_slice(&JOURNAL_FRAME_VERSION.to_be_bytes());
        out[10..12].copy_from_slice(&self.flags.to_be_bytes());
        out[12..20].copy_from_slice(&self.epoch.to_be_bytes());
        out[20..24].copy_from_slice(&self.source_block_number.to_be_bytes());
        out[24..28].copy_from_slice(&self.encoding_symbol_id.to_be_bytes());
        out[28..32].copy_from_slice(&self.source_symbol_count.to_be_bytes());
        out[32..36].copy_from_slice(&self.symbol_size.to_be_bytes());
        out[36..40].copy_from_slice(&self.payload_len.to_be_bytes());
        let header_crc = crc32(&out[0..40]);
        out[40..44].copy_from_slice(&header_crc.to_be_bytes());
        out
    }

    /// Parse a header from the front of `bytes`, validating magic, version, and
    /// the header CRC.
    fn decode(bytes: &[u8]) -> Result<Self, JournalFrameError> {
        if bytes.len() < JOURNAL_FRAME_HEADER_LEN {
            return Err(JournalFrameError::Truncated);
        }
        if bytes[0..8] != JOURNAL_FRAME_MAGIC {
            return Err(JournalFrameError::BadMagic);
        }
        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if version > JOURNAL_FRAME_VERSION {
            return Err(JournalFrameError::UnsupportedVersion(version));
        }
        let stored_crc = u32::from_be_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);
        if stored_crc != crc32(&bytes[0..40]) {
            return Err(JournalFrameError::HeaderChecksumMismatch);
        }
        Ok(Self {
            flags: u16::from_be_bytes([bytes[10], bytes[11]]),
            epoch: u64::from_be_bytes(read8(bytes, 12)),
            source_block_number: u32::from_be_bytes(read4(bytes, 20)),
            encoding_symbol_id: u32::from_be_bytes(read4(bytes, 24)),
            source_symbol_count: u32::from_be_bytes(read4(bytes, 28)),
            symbol_size: u32::from_be_bytes(read4(bytes, 32)),
            payload_len: u32::from_be_bytes(read4(bytes, 36)),
        })
    }
}

/// A complete journal frame: a header plus its symbol payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalFrame {
    /// Frame header.
    pub header: JournalFrameHeader,
    /// Symbol payload (`header.payload_len` bytes).
    pub payload: Vec<u8>,
}

impl JournalFrame {
    /// Build a frame for the given symbol, deriving `payload_len` from `payload`.
    #[must_use]
    pub fn new(
        epoch: u64,
        source_block_number: u32,
        encoding_symbol_id: u32,
        source_symbol_count: u32,
        symbol_size: u32,
        flags: u16,
        payload: Vec<u8>,
    ) -> Self {
        let payload_len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        Self {
            header: JournalFrameHeader {
                epoch,
                source_block_number,
                encoding_symbol_id,
                source_symbol_count,
                symbol_size,
                payload_len,
                flags,
            },
            payload,
        }
    }

    /// Total encoded length of this frame in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        JOURNAL_FRAME_HEADER_LEN + self.payload.len() + CRC_LEN
    }

    /// Append the encoded frame (header + payload + payload CRC) to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&crc32(&self.payload).to_be_bytes());
    }

    /// Encode the frame into a fresh buffer.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out);
        out
    }

    /// Decode a single frame from the front of `bytes`, returning the frame and
    /// the number of bytes consumed so a striped reader can scan the next frame.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), JournalFrameError> {
        let header = JournalFrameHeader::decode(bytes)?;
        let payload_len = header.payload_len as usize;
        let payload_start = JOURNAL_FRAME_HEADER_LEN;
        let payload_end = payload_start
            .checked_add(payload_len)
            .ok_or(JournalFrameError::PayloadTruncated)?;
        let crc_end = payload_end
            .checked_add(CRC_LEN)
            .ok_or(JournalFrameError::PayloadTruncated)?;
        if bytes.len() < crc_end {
            return Err(JournalFrameError::PayloadTruncated);
        }
        let payload = &bytes[payload_start..payload_end];
        let stored_crc = u32::from_be_bytes(read4(bytes, payload_end));
        if stored_crc != crc32(payload) {
            return Err(JournalFrameError::PayloadChecksumMismatch);
        }
        Ok((
            Self {
                header,
                payload: payload.to_vec(),
            },
            crc_end,
        ))
    }
}

/// Decode every intact frame in `bytes`, stopping at the first damaged/torn
/// frame.
///
/// Returns the recovered frames and the offset where scanning stopped, so a
/// caller can report how much of a striped journal survived.
#[must_use]
pub fn scan_frames(bytes: &[u8]) -> (Vec<JournalFrame>, usize) {
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        match JournalFrame::decode(&bytes[offset..]) {
            Ok((frame, consumed)) => {
                frames.push(frame);
                offset += consumed;
            }
            Err(_) => break,
        }
    }
    (frames, offset)
}

/// Identifies a RaptorQ source block within a trace epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockKey {
    /// Trace checkpoint epoch.
    pub epoch: u64,
    /// RaptorQ source block number within the epoch.
    pub source_block_number: u32,
}

/// Recovery-side decodability summary for one source block, reconstructed from
/// the surviving journal frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRecovery {
    /// Block this summary describes.
    pub key: BlockKey,
    /// Number of distinct encoding-symbol ids present for the block.
    pub distinct_symbols: usize,
    /// Source-symbol count K' required to RaptorQ-decode the block.
    pub source_symbol_count: u32,
}

impl BlockRecovery {
    /// Whether enough distinct symbols survived to RaptorQ-decode the block
    /// (`distinct_symbols >= source_symbol_count`).
    #[must_use]
    pub fn is_decodable(&self) -> bool {
        self.distinct_symbols as u64 >= u64::from(self.source_symbol_count)
    }
}

/// Summarize per-block decodability across the surviving frames.
///
/// Deterministically ordered by `(epoch, source_block_number)` — `BTree`-backed
/// so the result does not depend on `HashMap` iteration order (replay-stable).
///
/// Distinct symbols are counted by encoding-symbol id, and `source_symbol_count`
/// takes the largest K' advertised by the block's frames (they should agree).
#[must_use]
pub fn summarize_blocks(frames: &[JournalFrame]) -> Vec<BlockRecovery> {
    let mut blocks: BTreeMap<BlockKey, (BTreeSet<u32>, u32)> = BTreeMap::new();
    for frame in frames {
        let key = BlockKey {
            epoch: frame.header.epoch,
            source_block_number: frame.header.source_block_number,
        };
        let entry = blocks.entry(key).or_insert_with(|| (BTreeSet::new(), 0));
        entry.0.insert(frame.header.encoding_symbol_id);
        entry.1 = entry.1.max(frame.header.source_symbol_count);
    }
    blocks
        .into_iter()
        .map(|(key, (symbols, source_symbol_count))| BlockRecovery {
            key,
            distinct_symbols: symbols.len(),
            source_symbol_count,
        })
        .collect()
}

/// The blocks that survived with enough symbols to decode, in deterministic order.
#[must_use]
pub fn decodable_blocks(frames: &[JournalFrame]) -> Vec<BlockKey> {
    summarize_blocks(frames)
        .into_iter()
        .filter(BlockRecovery::is_decodable)
        .map(|block| block.key)
        .collect()
}

/// The highest epoch all of whose *present* blocks are decodable — the latest
/// checkpoint a recovery tool can fully reconstruct from the surviving stripes.
///
/// Completeness is judged over the blocks that actually appear in the journal;
/// detecting a wholly-missing block needs an epoch-manifest frame (a future
/// slice), so this answers "is every block we saw recoverable" for the epoch.
#[must_use]
pub fn latest_recoverable_epoch(frames: &[JournalFrame]) -> Option<u64> {
    let mut epoch_complete: BTreeMap<u64, bool> = BTreeMap::new();
    for block in summarize_blocks(frames) {
        let complete = epoch_complete.entry(block.key.epoch).or_insert(true);
        *complete = *complete && block.is_decodable();
    }
    epoch_complete
        .into_iter()
        .filter(|&(_, complete)| complete)
        .map(|(epoch, _)| epoch)
        .next_back()
}

/// Declares how many source blocks a checkpoint epoch was split into.
///
/// [`latest_recoverable_epoch`] can only judge the blocks that actually appear
/// in the surviving frames, so it cannot tell a *wholly missing* block from a
/// block that was never written. A writer emits one manifest per epoch (a
/// sidecar record, or a dedicated manifest frame in a future slice); recovery
/// consults it via [`epoch_is_complete`] / [`latest_complete_epoch`] to require
/// that every declared block survived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpochManifest {
    /// Trace checkpoint epoch the manifest describes.
    pub epoch: u64,
    /// Number of RaptorQ source blocks the epoch was split into.
    pub source_block_count: u32,
}

/// Magic identifying a persisted epoch-manifest record.
pub const EPOCH_MANIFEST_MAGIC: [u8; 4] = *b"ASRM";

/// Length of a persisted epoch-manifest record (magic + version + epoch +
/// block-count + CRC-32).
pub const EPOCH_MANIFEST_LEN: usize = 4 + 2 + 8 + 4 + 4;

impl EpochManifest {
    /// Serialize the manifest to its CRC-protected on-disk record so a writer
    /// can persist it alongside the stripe files. Big-endian, shares the journal
    /// version and CRC-32 with the frame format.
    #[must_use]
    pub fn encode(&self) -> [u8; EPOCH_MANIFEST_LEN] {
        let mut out = [0u8; EPOCH_MANIFEST_LEN];
        out[0..4].copy_from_slice(&EPOCH_MANIFEST_MAGIC);
        out[4..6].copy_from_slice(&JOURNAL_FRAME_VERSION.to_be_bytes());
        out[6..14].copy_from_slice(&self.epoch.to_be_bytes());
        out[14..18].copy_from_slice(&self.source_block_count.to_be_bytes());
        let crc = crc32(&out[0..18]);
        out[18..22].copy_from_slice(&crc.to_be_bytes());
        out
    }

    /// Parse a manifest record, validating magic, version, and CRC.
    ///
    /// # Errors
    ///
    /// Returns [`JournalFrameError`] for a short, mis-magicked, future-versioned,
    /// or corrupt record.
    pub fn decode(bytes: &[u8]) -> Result<Self, JournalFrameError> {
        if bytes.len() < EPOCH_MANIFEST_LEN {
            return Err(JournalFrameError::Truncated);
        }
        if bytes[0..4] != EPOCH_MANIFEST_MAGIC {
            return Err(JournalFrameError::BadMagic);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version > JOURNAL_FRAME_VERSION {
            return Err(JournalFrameError::UnsupportedVersion(version));
        }
        let stored_crc = u32::from_be_bytes(read4(bytes, 18));
        if stored_crc != crc32(&bytes[0..18]) {
            return Err(JournalFrameError::HeaderChecksumMismatch);
        }
        Ok(Self {
            epoch: u64::from_be_bytes(read8(bytes, 6)),
            source_block_count: u32::from_be_bytes(read4(bytes, 14)),
        })
    }
}

/// Self-describing decode metadata for an epoch.
///
/// The journal frames carry per-symbol `symbol_size` and per-block
/// `source_symbol_count`, but RaptorQ decode also needs the original object's
/// transfer length (`object_size`) to strip the last source block's symbol
/// padding, plus the `max_block_size` that fixed the source-block layout. None
/// of those three are recoverable from the surviving symbol frames alone, so a
/// writer persists this record next to the manifest. With it, recovery can
/// rebuild the exact [`crate::types::ObjectParams`] and decode the original
/// checkpoint bytes from any surviving `>= K'` symbols — not merely confirm
/// that enough survived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectParamsRecord {
    /// Trace checkpoint epoch this record describes.
    pub epoch: u64,
    /// Total size of the original checkpoint object in bytes (transfer length).
    pub object_size: u64,
    /// RaptorQ symbol size T in bytes (must match the frames).
    pub symbol_size: u16,
    /// Maximum source-block size that fixed the block layout during encode.
    pub max_block_size: u32,
}

/// Magic identifying a persisted object-params record (decode metadata).
pub const OBJECT_PARAMS_MAGIC: [u8; 4] = *b"ASRP";

/// Length of a persisted object-params record (magic + version + epoch +
/// object-size + symbol-size + max-block-size + CRC-32).
pub const OBJECT_PARAMS_RECORD_LEN: usize = 4 + 2 + 8 + 8 + 2 + 4 + 4;

impl ObjectParamsRecord {
    /// Serialize to the CRC-protected on-disk record. Big-endian; shares the
    /// journal version and CRC-32 with the frame and manifest formats.
    #[must_use]
    pub fn encode(&self) -> [u8; OBJECT_PARAMS_RECORD_LEN] {
        let mut out = [0u8; OBJECT_PARAMS_RECORD_LEN];
        out[0..4].copy_from_slice(&OBJECT_PARAMS_MAGIC);
        out[4..6].copy_from_slice(&JOURNAL_FRAME_VERSION.to_be_bytes());
        out[6..14].copy_from_slice(&self.epoch.to_be_bytes());
        out[14..22].copy_from_slice(&self.object_size.to_be_bytes());
        out[22..24].copy_from_slice(&self.symbol_size.to_be_bytes());
        out[24..28].copy_from_slice(&self.max_block_size.to_be_bytes());
        let crc = crc32(&out[0..28]);
        out[28..32].copy_from_slice(&crc.to_be_bytes());
        out
    }

    /// Parse an object-params record, validating magic, version, and CRC.
    ///
    /// # Errors
    ///
    /// Returns [`JournalFrameError`] for a short, mis-magicked, future-versioned,
    /// or corrupt record.
    pub fn decode(bytes: &[u8]) -> Result<Self, JournalFrameError> {
        if bytes.len() < OBJECT_PARAMS_RECORD_LEN {
            return Err(JournalFrameError::Truncated);
        }
        if bytes[0..4] != OBJECT_PARAMS_MAGIC {
            return Err(JournalFrameError::BadMagic);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version > JOURNAL_FRAME_VERSION {
            return Err(JournalFrameError::UnsupportedVersion(version));
        }
        let stored_crc = u32::from_be_bytes(read4(bytes, 28));
        if stored_crc != crc32(&bytes[0..28]) {
            return Err(JournalFrameError::HeaderChecksumMismatch);
        }
        Ok(Self {
            epoch: u64::from_be_bytes(read8(bytes, 6)),
            object_size: u64::from_be_bytes(read8(bytes, 14)),
            symbol_size: u16::from_be_bytes([bytes[22], bytes[23]]),
            max_block_size: u32::from_be_bytes(read4(bytes, 24)),
        })
    }

    /// The RaptorQ source-block layout `(source_blocks, symbols_per_block)` this
    /// object decodes with, mirroring the decoder's own block planner (a block
    /// per `max_block_size` chunk; `symbols_per_block` is the max `K` across
    /// blocks). Used to build the exact [`crate::types::ObjectParams`] for
    /// decode. Returns `(0, 0)` for an empty object.
    #[must_use]
    pub fn block_layout(&self) -> (u16, u16) {
        let object_size = self.object_size;
        let symbol_size = u64::from(self.symbol_size);
        let max_block_size = u64::from(self.max_block_size);
        if object_size == 0 || symbol_size == 0 || max_block_size == 0 {
            return (0, 0);
        }
        let mut blocks: u16 = 0;
        let mut max_k: u64 = 0;
        let mut offset: u64 = 0;
        while offset < object_size {
            let len = max_block_size.min(object_size - offset);
            let k = len.div_ceil(symbol_size);
            max_k = max_k.max(k);
            offset += len;
            blocks = blocks.saturating_add(1);
        }
        (blocks, u16::try_from(max_k).unwrap_or(u16::MAX))
    }
}

/// Whether every source block `0..manifest.source_block_count` in the epoch is
/// present *and* decodable among `frames`.
///
/// Unlike [`latest_recoverable_epoch`], this catches a wholly-missing block: a
/// block whose frames never made it to any surviving stripe fails the check.
#[must_use]
pub fn epoch_is_complete(frames: &[JournalFrame], manifest: EpochManifest) -> bool {
    let decodable: BTreeSet<u32> = summarize_blocks(frames)
        .into_iter()
        .filter(|block| block.key.epoch == manifest.epoch && block.is_decodable())
        .map(|block| block.key.source_block_number)
        .collect();
    (0..manifest.source_block_count).all(|sbn| decodable.contains(&sbn))
}

/// The highest epoch that is fully complete per its manifest — every declared
/// block present and decodable. This is the strongest "latest fully recoverable
/// checkpoint" answer, given per-epoch manifests.
#[must_use]
pub fn latest_complete_epoch(frames: &[JournalFrame], manifests: &[EpochManifest]) -> Option<u64> {
    manifests
        .iter()
        .filter(|manifest| epoch_is_complete(frames, **manifest))
        .map(|manifest| manifest.epoch)
        .max()
}

/// Plan that assigns each of `symbol_count` encoding symbols to one of
/// `stripe_count` striped journal files.
///
/// Symbols are round-robined by index, so every stripe carries an even
/// `floor`/`ceil` share and the loss of any single stripe removes at most
/// `ceil(symbol_count / stripe_count)` symbols. Striping across *different*
/// files (ideally different disks/dirs = different failure domains) is what lets
/// a RaptorQ block survive losing whole stripes: as long as at least the source
/// symbol count `K'` survive, the block still decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StripePlan {
    symbol_count: usize,
    stripe_count: usize,
}

impl StripePlan {
    /// Build a plan for `symbol_count` symbols across `stripe_count` stripes.
    /// Returns `None` if `stripe_count` is zero.
    #[must_use]
    pub const fn new(symbol_count: usize, stripe_count: usize) -> Option<Self> {
        if stripe_count == 0 {
            None
        } else {
            Some(Self {
                symbol_count,
                stripe_count,
            })
        }
    }

    /// Number of stripe files in the plan.
    #[must_use]
    pub const fn stripe_count(&self) -> usize {
        self.stripe_count
    }

    /// Stripe file index (0-based) the symbol at encoding position `index` is
    /// written to.
    #[must_use]
    pub const fn stripe_of(&self, index: usize) -> usize {
        index % self.stripe_count
    }

    /// Number of symbols that land on `stripe` (0 if `stripe` is out of range).
    #[must_use]
    pub const fn symbols_on_stripe(&self, stripe: usize) -> usize {
        if stripe >= self.stripe_count {
            return 0;
        }
        // positions stripe, stripe+S, stripe+2S, ... that are < symbol_count.
        if stripe >= self.symbol_count {
            0
        } else {
            // ceil((symbol_count - stripe) / stripe_count), const-friendly.
            (self.symbol_count - stripe + self.stripe_count - 1) / self.stripe_count
        }
    }

    /// Worst-case number of symbols still available after losing `lost` whole
    /// stripes — i.e. losing the `lost` *fullest* stripes.
    #[must_use]
    pub const fn symbols_surviving_loss(&self, lost: usize) -> usize {
        if lost >= self.stripe_count {
            return 0;
        }
        // With round-robin, the `symbol_count % stripe_count` lowest-indexed
        // stripes hold ceil(N/S); the rest hold floor(N/S). Losing the fullest
        // means losing as many ceil-sized stripes as possible first.
        let base = self.symbol_count / self.stripe_count; // floor share
        let remainder = self.symbol_count % self.stripe_count; // # of ceil stripes
        let ceil_lost = if lost < remainder { lost } else { remainder };
        let floor_lost = lost - ceil_lost;
        let lost_symbols = ceil_lost * (base + 1) + floor_lost * base;
        self.symbol_count - lost_symbols
    }

    /// Whether at least `source_symbols` (K') survive the loss of any `lost`
    /// stripes — i.e. the RaptorQ block still decodes after that failure-domain
    /// loss.
    #[must_use]
    pub const fn survives_stripe_loss(&self, source_symbols: usize, lost: usize) -> bool {
        self.symbols_surviving_loss(lost) >= source_symbols
    }
}

/// Serialize one checkpoint epoch's encoding symbols into per-stripe byte
/// streams following `plan`.
///
/// Returns `plan.stripe_count()` byte vectors; vector `i` is the concatenation
/// of the [`JournalFrame`]s for the symbols round-robined onto stripe `i`
/// (symbol position → [`StripePlan::stripe_of`]). A writer flushes vector `i` to
/// stripe file `i`, ideally on a distinct failure domain.
///
/// Recovery is the inverse: concatenate whatever stripe files survived and feed
/// the bytes to [`scan_frames`] then [`summarize_blocks`]. Losing whole stripes
/// is tolerated exactly as [`StripePlan::survives_stripe_loss`] predicts — as
/// long as at least `source_symbol_count` (K') symbols survive, the block still
/// RaptorQ-decodes.
#[must_use]
pub fn serialize_striped(
    epoch: u64,
    source_block_number: u32,
    source_symbol_count: u32,
    symbol_size: u32,
    flags: u16,
    symbols: &[(u32, Vec<u8>)],
    plan: &StripePlan,
) -> Vec<Vec<u8>> {
    let mut stripes = vec![Vec::new(); plan.stripe_count()];
    for (index, (encoding_symbol_id, payload)) in symbols.iter().enumerate() {
        let frame = JournalFrame::new(
            epoch,
            source_block_number,
            *encoding_symbol_id,
            source_symbol_count,
            symbol_size,
            flags,
            payload.clone(),
        );
        frame.encode_into(&mut stripes[plan.stripe_of(index)]);
    }
    stripes
}

/// One source block's encoding symbols for an epoch write.
///
/// `source_block_number` must be the block's index `0..N` within the epoch so
/// the emitted [`EpochManifest`] (which declares `source_block_count = N`) lines
/// up with [`epoch_is_complete`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSymbols {
    /// Block index within the epoch (`0..source_block_count`).
    pub source_block_number: u32,
    /// Source-symbol count K' needed to decode this block.
    pub source_symbol_count: u32,
    /// Symbol size T in bytes.
    pub symbol_size: u32,
    /// `(encoding_symbol_id, payload)` for every symbol generated for the block.
    pub symbols: Vec<(u32, Vec<u8>)>,
}

/// Serialize a whole checkpoint epoch — all of its source blocks — into
/// `stripe_count` per-stripe byte streams plus the matching [`EpochManifest`].
///
/// Each block's symbols are round-robined across the stripes (via
/// [`serialize_striped`]) and the per-stripe bytes are concatenated, so every
/// stripe file ends up with an even share of every block. The writer flushes
/// stripe `i` to file `i` (ideally a distinct failure domain) and persists the
/// returned manifest. Recovery is: concatenate the surviving stripe files →
/// [`scan_frames`] → [`latest_complete_epoch`] with the manifest.
///
/// Returns `None` if `stripe_count` is zero. `blocks` should carry
/// `source_block_number` values `0..blocks.len()`.
#[must_use]
pub fn serialize_epoch(
    epoch: u64,
    stripe_count: usize,
    flags: u16,
    blocks: &[BlockSymbols],
) -> Option<(Vec<Vec<u8>>, EpochManifest)> {
    if stripe_count == 0 {
        return None;
    }
    let mut stripes = vec![Vec::new(); stripe_count];
    for block in blocks {
        let plan = StripePlan::new(block.symbols.len(), stripe_count)?;
        let per_block = serialize_striped(
            epoch,
            block.source_block_number,
            block.source_symbol_count,
            block.symbol_size,
            flags,
            &block.symbols,
            &plan,
        );
        for (stripe, bytes) in per_block.into_iter().enumerate() {
            stripes[stripe].extend_from_slice(&bytes);
        }
    }
    let manifest = EpochManifest {
        epoch,
        source_block_count: u32::try_from(blocks.len()).unwrap_or(u32::MAX),
    };
    Some((stripes, manifest))
}

#[inline]
fn read4(bytes: &[u8], at: usize) -> [u8; 4] {
    [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]
}

#[inline]
fn read8(bytes: &[u8], at: usize) -> [u8; 8] {
    [
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
        bytes[at + 4],
        bytes[at + 5],
        bytes[at + 6],
        bytes[at + 7],
    ]
}

/// CRC-32/ISO-HDLC (the standard zlib/PNG CRC, reflected polynomial
/// `0xEDB88320`).
///
/// Bitwise so the table never needs to be carried; the journal frame sizes make
/// table lookup unnecessary on the cold checkpoint path.
#[must_use]
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}
