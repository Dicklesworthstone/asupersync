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
/// frame. Returns the recovered frames and the offset where scanning stopped,
/// so a caller can report how much of a striped journal survived.
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

/// Summarize per-block decodability across the surviving frames, deterministically
/// ordered by `(epoch, source_block_number)` — `BTree`-backed so the result does
/// not depend on `HashMap` iteration order (replay-stable).
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
/// `0xEDB88320`). Bitwise so the table never needs to be carried; the journal
/// frame sizes make table lookup unnecessary on the cold checkpoint path.
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
