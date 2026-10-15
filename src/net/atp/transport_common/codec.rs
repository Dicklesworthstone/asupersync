//! Negotiated payload codecs for ATP bulk data (br-asupersync-t1fblr.14).
//!
//! A sender that may compress puts a [`CodecOffer`] in a frame-header
//! extension of its hello. A receiver that can decode one of the offered
//! codecs answers with a [`CodecAccept`] extension on its hello ack. Only
//! after that accept may a data frame carry a compressed payload, and each
//! such frame names its codec and raw length in a [`ChunkCodec`] extension.
//!
//! Peers that predate this module never read frame-header extensions. An old
//! receiver ignores the offer and sends no accept, so the sender keeps every
//! payload raw; an old sender never offers. Manifests, hashes and content ids
//! always describe the raw bytes: a receiver decompresses a chunk before it
//! verifies anything.
//!
//! Each extension value is a fixed little-endian record that starts with a
//! version byte. An offer or accept with an unknown version or the wrong
//! length decodes to `None`, which means "no compression", never an error. A
//! data frame whose chunk record cannot be read is refused, because its
//! payload cannot be interpreted.

/// Frame-header extension id of a [`CodecOffer`], carried on a hello frame.
pub const CODEC_OFFER_EXTENSION: u16 = 0x0101;

/// Frame-header extension id of a [`CodecAccept`], carried on a hello ack.
pub const CODEC_ACCEPT_EXTENSION: u16 = 0x0102;

/// Frame-header extension id of a [`ChunkCodec`], carried on a data frame
/// whose payload is compressed.
pub const CHUNK_CODEC_EXTENSION: u16 = 0x0103;

/// Every frame-header extension id that ATP assigns. Ids must be unique; a
/// new extension takes an id that is not listed here.
pub const ASSIGNED_EXTENSION_IDS: [u16; 3] = [
    CODEC_OFFER_EXTENSION,
    CODEC_ACCEPT_EXTENSION,
    CHUNK_CODEC_EXTENSION,
];

/// The encoding version of the records in this module.
const RECORD_VERSION: u8 = 1;

/// A payload codec two peers can agree on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WireCodec {
    /// Zstandard (RFC 8878): one complete frame per chunk.
    Zstd,
}

impl WireCodec {
    /// Every codec, in order of preference.
    pub const ALL: [Self; 1] = [Self::Zstd];

    /// The codec's code in [`ChunkCodec`] and [`CodecAccept`] records.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Zstd => 1,
        }
    }

    /// The codec with `code`, if this build knows it.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Zstd),
            _ => None,
        }
    }

    /// The codec's bit in a [`CodecOffer`] or [`DecodeCapability`] set.
    #[must_use]
    pub const fn bit(self) -> u8 {
        1 << (self.code() - 1)
    }
}

/// A sender's offer: the codecs it can produce and the largest raw chunk it
/// will compress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodecOffer {
    /// Bit set of [`WireCodec::bit`] values.
    pub codecs: u8,
    /// Log2 of the largest window a compressed chunk will need.
    pub max_window_log: u8,
    /// The largest raw chunk the sender will compress, in bytes.
    pub max_chunk_raw: u32,
}

impl CodecOffer {
    /// An offer of `codecs` (a [`WireCodec::bit`] set).
    #[must_use]
    pub const fn new(codecs: u8, max_window_log: u8, max_chunk_raw: u32) -> Self {
        Self {
            codecs,
            max_window_log,
            max_chunk_raw,
        }
    }

    /// The extension value: version, codecs, window log, a reserved zero
    /// byte, then the chunk limit (little-endian).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![RECORD_VERSION, self.codecs, self.max_window_log, 0];
        bytes.extend_from_slice(&self.max_chunk_raw.to_le_bytes());
        bytes
    }

    /// Parses an extension value; `None` for an unknown version or length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let &[RECORD_VERSION, codecs, max_window_log, _, a, b, c, d] = bytes else {
            return None;
        };
        Some(Self::new(
            codecs,
            max_window_log,
            u32::from_le_bytes([a, b, c, d]),
        ))
    }

    /// Whether `accept` stays within this offer: an offered codec, limits no
    /// larger than offered, and at least one decode slot. A sender ignores an
    /// accept that does not, and sends raw.
    #[must_use]
    pub const fn admits(&self, accept: &CodecAccept) -> bool {
        self.codecs & accept.codec.bit() != 0
            && accept.max_window_log <= self.max_window_log
            && accept.max_chunk_raw <= self.max_chunk_raw
            && accept.decode_slots > 0
    }
}

/// What a receiver can decode, the input of [`negotiate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecodeCapability {
    /// Bit set of [`WireCodec::bit`] values.
    pub codecs: u8,
    /// Log2 of the largest window the receiver will allocate.
    pub max_window_log: u8,
    /// The largest raw chunk the receiver will decode, in bytes.
    pub max_chunk_raw: u32,
    /// How many chunks the receiver decodes concurrently (1 today).
    pub decode_slots: u8,
}

impl DecodeCapability {
    /// A capability for `codecs` (a [`WireCodec::bit`] set).
    #[must_use]
    pub const fn new(codecs: u8, max_window_log: u8, max_chunk_raw: u32) -> Self {
        Self {
            codecs,
            max_window_log,
            max_chunk_raw,
            decode_slots: 1,
        }
    }
}

/// A receiver's answer to an offer: the one codec chunks may use and the
/// limits every compressed chunk must respect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CodecAccept {
    /// The codec compressed chunks use.
    pub codec: WireCodec,
    /// Log2 of the largest window a compressed chunk may need.
    pub max_window_log: u8,
    /// The largest raw chunk that may be sent compressed, in bytes.
    pub max_chunk_raw: u32,
    /// How many chunks the receiver decodes concurrently.
    pub decode_slots: u8,
}

impl CodecAccept {
    /// The extension value: version, codec, window log, decode slots, then
    /// the chunk limit (little-endian).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![
            RECORD_VERSION,
            self.codec.code(),
            self.max_window_log,
            self.decode_slots,
        ];
        bytes.extend_from_slice(&self.max_chunk_raw.to_le_bytes());
        bytes
    }

    /// Parses an extension value; `None` for an unknown version, codec or
    /// length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let &[
            RECORD_VERSION,
            code,
            max_window_log,
            decode_slots,
            a,
            b,
            c,
            d,
        ] = bytes
        else {
            return None;
        };
        Some(Self {
            codec: WireCodec::from_code(code)?,
            max_window_log,
            max_chunk_raw: u32::from_le_bytes([a, b, c, d]),
            decode_slots,
        })
    }
}

/// The codec and raw length of one compressed data-frame payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChunkCodec {
    /// The codec of the payload.
    pub codec: WireCodec,
    /// The chunk's length before compression, in bytes.
    pub raw_len: u32,
}

impl ChunkCodec {
    /// A record for a `raw_len`-byte chunk compressed with `codec`.
    #[must_use]
    pub const fn new(codec: WireCodec, raw_len: u32) -> Self {
        Self { codec, raw_len }
    }

    /// The extension value: version, codec, then the raw length
    /// (little-endian).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![RECORD_VERSION, self.codec.code()];
        bytes.extend_from_slice(&self.raw_len.to_le_bytes());
        bytes
    }

    /// Parses an extension value; `None` for an unknown version, codec or
    /// length.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let &[RECORD_VERSION, code, a, b, c, d] = bytes else {
            return None;
        };
        Some(Self::new(
            WireCodec::from_code(code)?,
            u32::from_le_bytes([a, b, c, d]),
        ))
    }
}

/// The receiver's side of the negotiation.
///
/// Picks the first codec, in [`WireCodec::ALL`] order, that both sides
/// support, with the smaller of each limit. `None` (no compression) when
/// there is no common codec or a limit is zero.
#[must_use]
pub fn negotiate(local: &DecodeCapability, offer: &CodecOffer) -> Option<CodecAccept> {
    let common = local.codecs & offer.codecs;
    let codec = WireCodec::ALL
        .into_iter()
        .find(|codec| common & codec.bit() != 0)?;
    let max_window_log = local.max_window_log.min(offer.max_window_log);
    let max_chunk_raw = local.max_chunk_raw.min(offer.max_chunk_raw);
    if max_window_log == 0 || max_chunk_raw == 0 || local.decode_slots == 0 {
        return None;
    }
    Some(CodecAccept {
        codec,
        max_window_log,
        max_chunk_raw,
        decode_slots: local.decode_slots,
    })
}

/// Whether a sender compresses bulk data (br-asupersync-t1fblr.16).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompressionMode {
    /// Never offer or send compressed chunks (the default).
    #[default]
    Off,
    /// Offer zstd. Once the receiver accepts, send each chunk compressed
    /// whenever that makes it smaller, and raw otherwise. Without the `zstd`
    /// cargo feature this behaves as [`Self::Off`].
    Zstd,
    /// Offer zstd as [`Self::Zstd`] does, but spend no effort where it does
    /// not pay (br-asupersync-t1fblr.24). An entry whose name or first bytes
    /// mark an already-compressed format (zstd, gzip, xz, zip, JPEG, PNG,
    /// MP4, ...) is sent raw. A chunk that saves less than a twentieth of its
    /// size sends the next 1, 2, 4, ... up to 64 chunks of that entry raw
    /// before the next try. The decisions are deterministic. Without the
    /// `zstd` cargo feature this behaves as [`Self::Off`].
    Auto,
}

/// File-name extensions of formats that are already compressed.
const COMPRESSED_EXTENSIONS: [&str; 29] = [
    "zst", "gz", "tgz", "xz", "txz", "bz2", "lz4", "br", "zip", "7z", "rar", "jar", "apk", "jpg",
    "jpeg", "png", "gif", "webp", "avif", "heic", "mp4", "m4v", "mov", "webm", "mkv", "mp3", "ogg",
    "opus", "flac",
];

/// Whether `name`'s extension names an already-compressed format.
fn has_compressed_extension(name: &str) -> bool {
    let file = name.rsplit(['/', '\\']).next().unwrap_or(name);
    file.rsplit_once('.').is_some_and(|(stem, extension)| {
        !stem.is_empty()
            && COMPRESSED_EXTENSIONS
                .iter()
                .any(|known| extension.eq_ignore_ascii_case(known))
    })
}

/// Whether `head`, the first bytes of an entry, starts with the signature of
/// an already-compressed format: zstd, gzip, xz, bzip2, lz4, zip, 7z, JPEG,
/// PNG, GIF, WebP, ISO base media (MP4, MOV, HEIC, AVIF), Matroska/WebM, Ogg,
/// FLAC or ID3-tagged MP3.
fn has_compressed_signature(head: &[u8]) -> bool {
    const PREFIXES: [&[u8]; 14] = [
        &[0x28, 0xB5, 0x2F, 0xFD],
        &[0x1F, 0x8B],
        &[0xFD, b'7', b'z', b'X', b'Z', 0x00],
        b"BZh",
        &[0x04, 0x22, 0x4D, 0x18],
        &[b'P', b'K', 0x03, 0x04],
        &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C],
        &[0xFF, 0xD8, 0xFF],
        &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
        b"GIF8",
        &[0x1A, 0x45, 0xDF, 0xA3],
        b"OggS",
        b"fLaC",
        b"ID3",
    ];
    PREFIXES.iter().any(|prefix| head.starts_with(prefix))
        || (head.starts_with(b"RIFF") && head.get(8..12) == Some(b"WEBP".as_slice()))
        || head.get(4..8) == Some(b"ftyp".as_slice())
}

/// The longest run of chunks [`CompressionMode::Auto`] sends raw before it
/// tries an entry's data again.
const MAX_RAW_RUN: u32 = 64;

/// Which chunks of one entry a sender tries to compress
/// (br-asupersync-t1fblr.24).
///
/// Under [`CompressionMode::Zstd`] every chunk is tried, and under
/// [`CompressionMode::Off`] none. Under [`CompressionMode::Auto`]:
/// - an entry whose name or first bytes mark an already-compressed format
///   (zstd, gzip, xz, zip, JPEG, PNG, MP4, ...) is never tried;
/// - a tried chunk that saves less than a twentieth of its size is a miss.
///   After the first miss the next chunk goes raw, after the second the next
///   two, then four, and so on up to 64, before the next try. A chunk that
///   saves at least a twentieth ends the backoff.
///
/// The decisions depend only on the entry's name, its bytes and the order of
/// its chunks, so a transfer makes the same ones every time. Crate-private:
/// its inputs will grow with the goodput rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EntryCompression {
    mode: CompressionMode,
    /// The entry is an already-compressed format.
    skip: bool,
    /// Chunks still to send raw before the next try.
    raw_left: u32,
    /// The raw run that follows the next miss (0 before any miss).
    run: u32,
}

impl EntryCompression {
    /// The decisions for the entry named `name` (a path; only its extension
    /// is read) under `mode`.
    #[must_use]
    pub(crate) fn new(mode: CompressionMode, name: &str) -> Self {
        Self {
            mode,
            skip: mode == CompressionMode::Auto && has_compressed_extension(name),
            raw_left: 0,
            run: 0,
        }
    }

    /// Whether to try compressing `chunk`, the entry's bytes at `offset`.
    /// After a `true`, report the outcome with [`Self::record`]. Only
    /// compressing builds (`zstd`) decide anything.
    #[cfg_attr(not(feature = "zstd"), allow(dead_code))]
    pub(crate) fn should_try(&mut self, offset: u64, chunk: &[u8]) -> bool {
        match self.mode {
            CompressionMode::Off => false,
            CompressionMode::Zstd => true,
            CompressionMode::Auto => {
                if offset == 0 && has_compressed_signature(chunk) {
                    self.skip = true;
                }
                if self.skip {
                    return false;
                }
                if self.raw_left > 0 {
                    self.raw_left -= 1;
                    return false;
                }
                true
            }
        }
    }

    /// Records how a tried chunk of `raw_len` bytes fared: compressed to
    /// `compressed_len` bytes, or `None` when it went raw.
    #[cfg_attr(not(feature = "zstd"), allow(dead_code))]
    pub(crate) fn record(&mut self, raw_len: usize, compressed_len: Option<usize>) {
        if self.mode != CompressionMode::Auto {
            return;
        }
        let saved = compressed_len.map_or(0, |len| raw_len.saturating_sub(len));
        if saved > 0 && saved >= raw_len / 20 {
            self.run = 0;
        } else {
            self.run = (self.run * 2).clamp(1, MAX_RAW_RUN);
            self.raw_left = self.run;
        }
    }

    /// [`compress_chunk`] for the entry's bytes at `offset`, when these
    /// decisions say to try.
    #[cfg(feature = "zstd")]
    pub(crate) fn compress(
        &mut self,
        accept: &CodecAccept,
        offset: u64,
        raw: &[u8],
    ) -> Option<(ChunkCodec, Vec<u8>)> {
        if !self.should_try(offset, raw) {
            return None;
        }
        let compressed = compress_chunk(accept, raw);
        self.record(
            raw.len(),
            compressed.as_ref().map(|(_, payload)| payload.len()),
        );
        compressed
    }
}

/// Why a compressed chunk was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChunkCodecError {
    /// The chunk is compressed, but no codec was accepted for the session.
    #[error("compressed chunk without a negotiated codec")]
    NotNegotiated,
    /// The chunk's extension record is malformed or names another codec.
    #[error("chunk codec record does not match the negotiated codec")]
    CodecMismatch,
    /// The declared raw length exceeds the negotiated or remaining limit.
    #[error("chunk raw length {raw_len} exceeds the limit {limit}")]
    TooLarge {
        /// The declared raw length.
        raw_len: u64,
        /// The limit it broke.
        limit: u64,
    },
    /// The payload does not decode to exactly the declared raw bytes.
    #[error("compressed chunk does not decode: {0}")]
    Corrupt(String),
}

/// The zstd window log of a frame whose content is `raw_len` bytes: a
/// single-segment frame's window is its content size.
#[cfg(feature = "zstd")]
fn window_log_for(raw_len: usize) -> u8 {
    u8::try_from(raw_len.max(1).next_power_of_two().ilog2()).unwrap_or(u8::MAX)
}

/// What this build can decode: zstd chunks of up to `max_chunk_raw` bytes
/// when the `zstd` feature is on, nothing otherwise.
#[must_use]
pub fn local_decode_capability(max_chunk_raw: u32) -> DecodeCapability {
    #[cfg(feature = "zstd")]
    {
        let window_log =
            u8::try_from(max_chunk_raw.max(1).next_power_of_two().ilog2()).unwrap_or(u8::MAX);
        DecodeCapability::new(WireCodec::Zstd.bit(), window_log, max_chunk_raw)
    }
    #[cfg(not(feature = "zstd"))]
    {
        DecodeCapability::new(0, 0, max_chunk_raw)
    }
}

/// The offer a sender makes for `mode` with chunks of up to `chunk_size`
/// bytes, or `None` when it will not compress.
#[must_use]
pub fn local_offer(mode: CompressionMode, chunk_size: usize) -> Option<CodecOffer> {
    match mode {
        CompressionMode::Off => None,
        CompressionMode::Zstd | CompressionMode::Auto => {
            #[cfg(feature = "zstd")]
            {
                let max_chunk_raw = u32::try_from(chunk_size).ok()?;
                Some(CodecOffer::new(
                    WireCodec::Zstd.bit(),
                    window_log_for(chunk_size),
                    max_chunk_raw,
                ))
            }
            #[cfg(not(feature = "zstd"))]
            {
                let _ = chunk_size;
                None
            }
        }
    }
}

/// An upper bound on the bytes a [`CHUNK_CODEC_EXTENSION`] record adds to a
/// frame header: the varint id and length, and the 6-byte record.
pub const CHUNK_CODEC_OVERHEAD: usize = 16;

/// Compresses `raw` for a session that accepted `accept`.
///
/// `None` when the chunk is over the accepted limits, or when compression
/// would not save at least [`CHUNK_CODEC_OVERHEAD`]; the chunk is then sent
/// raw. So a compressed frame is never larger than the raw frame would have
/// been.
#[cfg(feature = "zstd")]
#[must_use]
pub fn compress_chunk(accept: &CodecAccept, raw: &[u8]) -> Option<(ChunkCodec, Vec<u8>)> {
    let raw_len = u32::try_from(raw.len()).ok()?;
    if raw_len > accept.max_chunk_raw || window_log_for(raw.len()) > accept.max_window_log {
        return None;
    }
    let WireCodec::Zstd = accept.codec;
    // The chunk is covered by the transfer's SHA-256, so the frame skips
    // zstd's own content checksum.
    let params =
        asupersync_zstd::EncodeParams::new(asupersync_zstd::Level::Fast).with_checksum(false);
    let compressed = asupersync_zstd::encode_all(raw, &params);
    (compressed.len() + CHUNK_CODEC_OVERHEAD <= raw.len())
        .then(|| (ChunkCodec::new(WireCodec::Zstd, raw_len), compressed))
}

/// Decodes a compressed chunk into `out` (cleared first).
///
/// `record` is the chunk's extension value, `accept` the session's accepted
/// codec (if any), and `remaining` the bytes the current entry may still
/// receive. The output never exceeds the declared raw length, which is
/// checked against both limits before anything is allocated.
#[cfg(feature = "zstd")]
pub fn decompress_chunk(
    record: &[u8],
    accept: Option<&CodecAccept>,
    remaining: u64,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), ChunkCodecError> {
    let accept = accept.ok_or(ChunkCodecError::NotNegotiated)?;
    let chunk = ChunkCodec::from_bytes(record)
        .filter(|chunk| chunk.codec == accept.codec)
        .ok_or(ChunkCodecError::CodecMismatch)?;
    let raw_len = u64::from(chunk.raw_len);
    let limit = u64::from(accept.max_chunk_raw).min(remaining);
    if raw_len > limit {
        return Err(ChunkCodecError::TooLarge { raw_len, limit });
    }
    let raw_len =
        usize::try_from(chunk.raw_len).map_err(|_| ChunkCodecError::TooLarge { raw_len, limit })?;
    let limits = asupersync_zstd::DecodeLimits::new(raw_len)
        .with_max_window(
            1_usize
                .checked_shl(u32::from(accept.max_window_log))
                .unwrap_or(0),
        )
        .with_require_content_size(true)
        .with_allow_skippable_frames(false);
    // Decoding appends to the cleared scratch buffer, so a receiver reuses
    // one allocation for every chunk, with no zero fill and no copy.
    out.clear();
    let written = asupersync_zstd::decode_append(payload, out, &limits)
        .map_err(|error| ChunkCodecError::Corrupt(error.to_string()))?;
    if written != raw_len {
        return Err(ChunkCodecError::Corrupt(format!(
            "decoded {written} bytes, declared {raw_len}"
        )));
    }
    Ok(())
}

/// Decoding without the `zstd` feature: this build never accepts a codec,
/// so any compressed chunk is a protocol violation.
#[cfg(not(feature = "zstd"))]
pub fn decompress_chunk(
    _record: &[u8],
    _accept: Option<&CodecAccept>,
    _remaining: u64,
    _payload: &[u8],
    _out: &mut Vec<u8>,
) -> Result<(), ChunkCodecError> {
    Err(ChunkCodecError::NotNegotiated)
}

/// How many chunks a sender compresses at once by default
/// (br-asupersync-t1fblr.25).
pub const DEFAULT_COMPRESSION_PARALLELISM: usize = 4;

/// One chunk as the sender emits it: its entry and offset, its raw bytes,
/// and its compressed form when compression was tried and paid.
#[cfg(feature = "zstd")]
pub(crate) struct PipelinedChunk {
    pub(crate) index: u32,
    pub(crate) offset: u64,
    pub(crate) raw: Vec<u8>,
    pub(crate) compressed: Option<(ChunkCodec, Vec<u8>)>,
}

/// A raw chunk and what [`compress_chunk`] made of it.
#[cfg(feature = "zstd")]
type CompressedChunk = (Vec<u8>, Option<(ChunkCodec, Vec<u8>)>);

#[cfg(feature = "zstd")]
enum PipelineSlot {
    /// Decided at push time: `tried` says whether the outcome feeds the
    /// entry's decisions.
    Ready { chunk: PipelinedChunk, tried: bool },
    /// Compressing on the blocking pool.
    Running {
        index: u32,
        offset: u64,
        handle: crate::runtime::spawn_blocking::DrainedBlockingHandle<CompressedChunk>,
    },
}

/// Compresses chunks up to `depth` at a time on the runtime's blocking pool
/// and hands them back in the order they came in (br-asupersync-t1fblr.25).
/// Chunks of consecutive entries share the pipeline, so a tree of small
/// files compresses in parallel too.
///
/// Each chunk is one independent zstd frame, so the bytes sent do not depend
/// on `depth` under [`CompressionMode::Zstd`]. Under [`CompressionMode::Auto`]
/// a chunk's outcome reaches its entry's decisions when it leaves the
/// pipeline while that entry is still being read, so a decision sees the
/// outcomes of the chunks at least `depth` places earlier, the same with or
/// without a pool.
///
/// The jobs are owned by the caller's region ([`Cx::spawn_blocking_drained`]):
/// dropping the pipeline cancels the queued ones and its region waits for the
/// running ones, so nothing is detached. Without a blocking pool or spawn
/// authority (the lab runtime, a test `Cx`), chunks are compressed inline.
#[cfg(feature = "zstd")]
pub(crate) struct ChunkPipeline {
    accept: CodecAccept,
    depth: usize,
    slots: std::collections::VecDeque<PipelineSlot>,
    /// Chunks handed to the blocking pool, for tests.
    #[cfg(test)]
    pooled: usize,
}

#[cfg(feature = "zstd")]
impl ChunkPipeline {
    /// A pipeline compressing for `accept`, at most `depth` (at least 1)
    /// chunks at once.
    pub(crate) fn new(accept: CodecAccept, depth: usize) -> Self {
        Self {
            accept,
            depth: depth.max(1),
            slots: std::collections::VecDeque::new(),
            #[cfg(test)]
            pooled: 0,
        }
    }

    /// Whether `depth` chunks are queued: take one with [`Self::next`] before
    /// pushing another.
    pub(crate) fn is_full(&self) -> bool {
        self.slots.len() >= self.depth
    }

    /// Queues `raw`, the bytes at `offset` of entry `index`. When `entry` (that
    /// entry's decisions) decides to try, the chunk is compressed on the
    /// blocking pool (inline without one); otherwise it stays raw.
    pub(crate) fn push(
        &mut self,
        cx: &crate::cx::Cx,
        entry: &mut EntryCompression,
        index: u32,
        offset: u64,
        raw: Vec<u8>,
    ) {
        if !entry.should_try(offset, &raw) {
            self.slots.push_back(PipelineSlot::Ready {
                chunk: PipelinedChunk {
                    index,
                    offset,
                    raw,
                    compressed: None,
                },
                tried: false,
            });
            return;
        }
        let accept = self.accept;
        // The chunk waits in a slot the job takes it from: a refused spawn
        // never ran the job, so the chunk is still there to compress inline.
        let slot = std::sync::Arc::new(parking_lot::Mutex::new(Some(raw)));
        let job_slot = std::sync::Arc::clone(&slot);
        let spawned = cx.spawn_blocking_drained(move |_| {
            let raw = job_slot.lock().take().unwrap_or_default();
            let compressed = compress_chunk(&accept, &raw);
            (raw, compressed)
        });
        match spawned {
            Ok(handle) => {
                #[cfg(test)]
                {
                    self.pooled += 1;
                }
                self.slots.push_back(PipelineSlot::Running {
                    index,
                    offset,
                    handle,
                });
            }
            Err(_) => {
                let raw = slot.lock().take().unwrap_or_default();
                let compressed = compress_chunk(&accept, &raw);
                self.slots.push_back(PipelineSlot::Ready {
                    chunk: PipelinedChunk {
                        index,
                        offset,
                        raw,
                        compressed,
                    },
                    tried: true,
                });
            }
        }
    }

    /// The oldest queued chunk, once it is ready, or `None` when the pipeline
    /// is empty. A tried chunk of entry `current` records its outcome in
    /// `entry`, that entry's decisions; outcomes of earlier entries no longer
    /// decide anything.
    pub(crate) async fn next(
        &mut self,
        current: u32,
        entry: &mut EntryCompression,
    ) -> Option<Result<PipelinedChunk, crate::runtime::JoinError>> {
        let (chunk, tried) = match self.slots.front_mut()? {
            PipelineSlot::Ready { .. } => match self.slots.pop_front() {
                Some(PipelineSlot::Ready { chunk, tried }) => (chunk, tried),
                _ => return None,
            },
            PipelineSlot::Running {
                index,
                offset,
                handle,
            } => {
                let (index, offset) = (*index, *offset);
                // A dropped wait leaves the slot queued, so a later call
                // resumes the same join.
                let joined = handle.join().await;
                self.slots.pop_front();
                match joined {
                    Ok((raw, compressed)) => (
                        PipelinedChunk {
                            index,
                            offset,
                            raw,
                            compressed,
                        },
                        true,
                    ),
                    Err(error) => return Some(Err(error)),
                }
            }
        };
        if tried && chunk.index == current {
            entry.record(
                chunk.raw.len(),
                chunk.compressed.as_ref().map(|(_, payload)| payload.len()),
            );
        }
        Some(Ok(chunk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn records_round_trip() {
        let offer = CodecOffer::new(WireCodec::Zstd.bit(), 18, 256 * 1024);
        assert_eq!(offer.to_bytes().len(), 8);
        assert_eq!(CodecOffer::from_bytes(&offer.to_bytes()), Some(offer));
        let accept = negotiate(&DecodeCapability::new(1, 20, 1 << 20), &offer).unwrap();
        assert_eq!(CodecAccept::from_bytes(&accept.to_bytes()), Some(accept));
        let chunk = ChunkCodec::new(WireCodec::Zstd, 1234);
        assert_eq!(chunk.to_bytes(), [1, 1, 0xD2, 0x04, 0, 0]);
        assert_eq!(ChunkCodec::from_bytes(&chunk.to_bytes()), Some(chunk));
    }

    #[test]
    fn unknown_versions_codecs_and_lengths_mean_no_compression() {
        let offer = CodecOffer::new(1, 18, 4096).to_bytes();
        let mut future = offer.clone();
        future[0] = 2;
        assert_eq!(CodecOffer::from_bytes(&future), None);
        assert_eq!(CodecOffer::from_bytes(&offer[..7]), None);
        let mut longer = offer;
        longer.push(0);
        assert_eq!(CodecOffer::from_bytes(&longer), None);
        assert_eq!(ChunkCodec::from_bytes(&[1, 9, 0, 0, 0, 0]), None, "codec 9");
        assert_eq!(CodecAccept::from_bytes(&[1, 9, 20, 1, 0, 0, 1, 0]), None);
        assert_eq!(ChunkCodec::from_bytes(&[]), None);
    }

    #[test]
    fn negotiation_takes_the_common_codec_and_the_smaller_limits() {
        let local = DecodeCapability::new(WireCodec::Zstd.bit(), 20, 1 << 20);
        let accept = negotiate(&local, &CodecOffer::new(1, 18, 256 * 1024)).unwrap();
        assert_eq!(accept.codec, WireCodec::Zstd);
        assert_eq!(
            (accept.max_window_log, accept.max_chunk_raw),
            (18, 256 * 1024)
        );
        let accept = negotiate(&local, &CodecOffer::new(1, 27, 8 << 20)).unwrap();
        assert_eq!((accept.max_window_log, accept.max_chunk_raw), (20, 1 << 20));
        assert_eq!(accept.decode_slots, 1);
        // Nothing in common, or a receiver that decodes nothing.
        assert_eq!(negotiate(&local, &CodecOffer::new(0b10, 18, 4096)), None);
        assert_eq!(
            negotiate(
                &DecodeCapability::new(0, 0, 4096),
                &CodecOffer::new(1, 18, 4096)
            ),
            None
        );
        assert_eq!(negotiate(&local, &CodecOffer::new(1, 18, 0)), None);
    }

    #[test]
    fn a_sender_admits_only_accepts_within_its_offer() {
        let offer = CodecOffer::new(WireCodec::Zstd.bit(), 18, 256 * 1024);
        let fitting = negotiate(&DecodeCapability::new(1, 20, 1 << 20), &offer).unwrap();
        assert!(offer.admits(&fitting));
        let mut wider = fitting;
        wider.max_chunk_raw += 1;
        assert!(!offer.admits(&wider), "a larger chunk limit than offered");
        let mut deeper = fitting;
        deeper.max_window_log = 19;
        assert!(!offer.admits(&deeper), "a larger window than offered");
        let mut no_slots = fitting;
        no_slots.decode_slots = 0;
        assert!(!offer.admits(&no_slots));
        assert!(
            !CodecOffer::new(0, 18, 256 * 1024).admits(&fitting),
            "codec not offered"
        );
    }

    #[test]
    fn extension_ids_are_unique() {
        let unique: BTreeSet<u16> = ASSIGNED_EXTENSION_IDS.into_iter().collect();
        assert_eq!(unique.len(), ASSIGNED_EXTENSION_IDS.len());
    }

    #[test]
    fn off_never_offers() {
        assert_eq!(local_offer(CompressionMode::Off, 256 * 1024), None);
        assert_eq!(CompressionMode::default(), CompressionMode::Off);
    }

    /// Auto never tries an entry whose name or first bytes mark a compressed
    /// format; Zstd tries everything and Off nothing.
    #[test]
    fn auto_skips_already_compressed_entries() {
        let text = b"plain text, plain text, plain text".as_slice();
        let tries = |mode, name: &str, offset, chunk: &[u8]| {
            EntryCompression::new(mode, name).should_try(offset, chunk)
        };
        for name in [
            "photo.JPG",
            "dir/backup.tar.gz",
            "dir\\logs.zst",
            "clip.mp4",
            "a.b.flac",
        ] {
            assert!(!tries(CompressionMode::Auto, name, 0, text), "{name}");
            assert!(tries(CompressionMode::Zstd, name, 0, text), "{name}");
        }
        for name in [
            "notes.txt",
            "Makefile",
            ".gz",
            "gz",
            "archive.gz.txt",
            "dir.zip/a.rs",
        ] {
            assert!(tries(CompressionMode::Auto, name, 0, text), "{name}");
        }
        let mut webp = b"RIFF\x10\x00\x00\x00WEBPVP8 ".to_vec();
        webp.extend_from_slice(text);
        let mut mp4 = b"\x00\x00\x00\x18ftypisom".to_vec();
        mp4.extend_from_slice(text);
        let signatures: [&[u8]; 6] = [
            &[0x1F, 0x8B, 0x08, 0x00, 0x00],
            &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00],
            b"PK\x03\x04 a zip entry",
            &[0x28, 0xB5, 0x2F, 0xFD, 0x24],
            &webp,
            &mp4,
        ];
        for head in signatures {
            assert!(
                !tries(CompressionMode::Auto, "data.bin", 0, head),
                "{head:?}"
            );
            // A signature counts only at the start of the entry.
            assert!(
                tries(CompressionMode::Auto, "data.bin", 1, head),
                "{head:?}"
            );
            assert!(
                tries(CompressionMode::Zstd, "data.bin", 0, head),
                "{head:?}"
            );
        }
        let mut gzip = EntryCompression::new(CompressionMode::Auto, "data.bin");
        assert!(!gzip.should_try(0, &[0x1F, 0x8B, 0x08]));
        assert!(!gzip.should_try(4096, text), "the whole entry stays raw");
        assert!(!tries(CompressionMode::Off, "notes.txt", 0, text));
    }

    /// The chunks Auto tries over `outcomes`, where `outcomes(i)` is the
    /// compressed size of a tried 1000-byte chunk `i` (`None`: sent raw).
    fn auto_tries(chunks: u64, outcomes: impl Fn(u64) -> Option<usize>) -> Vec<u64> {
        let mut entry = EntryCompression::new(CompressionMode::Auto, "data.bin");
        let mut tried = Vec::new();
        for index in 0..chunks {
            if entry.should_try(index * 1000, b"chunk") {
                tried.push(index);
                entry.record(1000, outcomes(index));
            }
        }
        tried
    }

    /// Misses double the raw run up to 64 chunks; a chunk that saves a
    /// twentieth ends the backoff, and one that saves less is a miss.
    #[test]
    fn auto_backs_off_from_data_that_does_not_compress() {
        assert_eq!(
            auto_tries(200, |_| None),
            [0, 2, 5, 10, 19, 36, 69, 134, 199]
        );
        // Saving 40 of 1000 bytes is a miss; 50 is not.
        assert_eq!(auto_tries(11, |_| Some(960)), [0, 2, 5, 10]);
        assert_eq!(auto_tries(5, |_| Some(950)), [0, 1, 2, 3, 4]);
        // Compressible data after a miss is tried at once after the next hit.
        assert_eq!(
            auto_tries(12, |index| (index >= 5).then_some(100)),
            [0, 2, 5, 6, 7, 8, 9, 10, 11]
        );
        // Zstd tries every chunk whatever happens.
        let mut zstd = EntryCompression::new(CompressionMode::Zstd, "photo.jpg");
        for index in 0..10 {
            assert!(zstd.should_try(index, &[0xFF, 0xD8, 0xFF]));
            zstd.record(1000, None);
        }
    }

    #[cfg(not(feature = "zstd"))]
    #[test]
    fn without_the_feature_nothing_is_offered_or_accepted() {
        assert_eq!(local_offer(CompressionMode::Zstd, 256 * 1024), None);
        let local = local_decode_capability(1 << 20);
        assert_eq!(negotiate(&local, &CodecOffer::new(1, 18, 4096)), None);
        assert_eq!(
            decompress_chunk(&[1, 1, 4, 0, 0, 0], None, 10, b"x", &mut Vec::new()),
            Err(ChunkCodecError::NotNegotiated)
        );
    }

    #[cfg(feature = "zstd")]
    mod zstd {
        use super::super::*;

        fn session() -> CodecAccept {
            let offer = local_offer(CompressionMode::Zstd, 256 * 1024).unwrap();
            negotiate(&local_decode_capability(1 << 20), &offer).unwrap()
        }

        #[test]
        fn compressible_chunks_round_trip() {
            let accept = session();
            let raw: Vec<u8> = b"asupersync transfer protocol "
                .iter()
                .copied()
                .cycle()
                .take(200_000)
                .collect();
            let (chunk, payload) = compress_chunk(&accept, &raw).unwrap();
            assert!(payload.len() < raw.len() / 10);
            let mut out = Vec::new();
            decompress_chunk(
                &chunk.to_bytes(),
                Some(&accept),
                1 << 30,
                &payload,
                &mut out,
            )
            .unwrap();
            assert_eq!(out, raw);
        }

        /// Auto offers what Zstd offers, compresses text, and stops trying
        /// noise and named or signed compressed formats.
        #[test]
        fn auto_compresses_where_it_pays() {
            assert_eq!(
                local_offer(CompressionMode::Auto, 256 * 1024),
                local_offer(CompressionMode::Zstd, 256 * 1024)
            );
            let accept = session();
            let text: Vec<u8> = b"asupersync transfer protocol "
                .iter()
                .copied()
                .cycle()
                .take(64 * 1024)
                .collect();
            let mut state = 3_u64;
            let noise: Vec<u8> = (0..64 * 1024)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    state.to_be_bytes()[0]
                })
                .collect();
            let compressed = |mode, name: &str, data: &[u8]| -> Vec<bool> {
                let mut entry = EntryCompression::new(mode, name);
                (0..8_u64)
                    .map(|index| entry.compress(&accept, index * 65_536, data).is_some())
                    .collect()
            };
            assert_eq!(
                compressed(CompressionMode::Auto, "log.txt", &text),
                [true; 8]
            );
            assert_eq!(
                compressed(CompressionMode::Auto, "log.txt", &noise),
                [false; 8]
            );
            assert_eq!(
                compressed(CompressionMode::Auto, "log.png", &text),
                [false; 8]
            );
            assert_eq!(
                compressed(CompressionMode::Zstd, "log.png", &text),
                [true; 8]
            );
            let mut gzip_head = vec![0x1F, 0x8B];
            gzip_head.extend_from_slice(&text[2..]);
            let mut entry = EntryCompression::new(CompressionMode::Auto, "log.bin");
            assert!(entry.compress(&accept, 0, &gzip_head).is_none());
            assert!(entry.compress(&accept, 65_536, &text).is_none());
        }

        /// Chunks of different kinds and sizes, so pool jobs finish out of
        /// order: text, noise every third chunk.
        fn mixed_chunks() -> Vec<Vec<u8>> {
            let mut state = 5_u64;
            (0..12_usize)
                .map(|index| {
                    let len = 4096 + (index % 4) * 60_000;
                    if index % 3 == 2 {
                        (0..len)
                            .map(|_| {
                                state = state
                                    .wrapping_mul(6_364_136_223_846_793_005)
                                    .wrapping_add(1_442_695_040_888_963_407);
                                state.to_be_bytes()[0]
                            })
                            .collect()
                    } else {
                        b"asupersync transfer protocol "
                            .iter()
                            .copied()
                            .cycle()
                            .take(len)
                            .collect()
                    }
                })
                .collect()
        }

        /// The entry chunk `position` belongs to: entries of four chunks.
        fn entry_of(position: usize) -> u32 {
            u32::try_from(position / 4).unwrap()
        }

        /// Runs `chunks` through a pipeline of `depth`, four chunks per
        /// entry, taking one out whenever it is full. Returns what came out,
        /// in order, and how many chunks went to the blocking pool.
        async fn run_pipeline(
            cx: &crate::cx::Cx,
            accept: CodecAccept,
            depth: usize,
            chunks: Vec<Vec<u8>>,
        ) -> (Vec<PipelinedChunk>, usize) {
            let mut entry = EntryCompression::new(CompressionMode::Zstd, "data.bin");
            let mut pipeline = ChunkPipeline::new(accept, depth);
            let mut out = Vec::new();
            let (mut offset, mut current) = (0_u64, 0_u32);
            for (position, chunk) in chunks.into_iter().enumerate() {
                if pipeline.is_full() {
                    let next = pipeline.next(current, &mut entry).await;
                    out.push(next.expect("a queued chunk").expect("joined"));
                }
                if entry_of(position) != current {
                    current = entry_of(position);
                    offset = 0;
                    entry = EntryCompression::new(CompressionMode::Zstd, "data.bin");
                }
                let len = u64::try_from(chunk.len()).unwrap();
                pipeline.push(cx, &mut entry, current, offset, chunk);
                assert!(pipeline.slots.len() <= depth, "at most {depth} in flight");
                offset += len;
            }
            while let Some(next) = pipeline.next(current, &mut entry).await {
                out.push(next.expect("joined"));
            }
            (out, pipeline.pooled)
        }

        /// Every chunk came back in order, with its entry and offset, and with
        /// the bytes sequential compression gives.
        fn assert_sequential(accept: &CodecAccept, chunks: &[Vec<u8>], out: &[PipelinedChunk]) {
            assert_eq!(out.len(), chunks.len());
            let mut offset = 0_u64;
            for (position, (chunk, got)) in chunks.iter().zip(out).enumerate() {
                if position % 4 == 0 {
                    offset = 0;
                }
                assert_eq!(got.index, entry_of(position), "chunk {position}");
                assert_eq!(got.offset, offset, "chunk {position}");
                assert_eq!(&got.raw, chunk, "chunk {position}");
                assert_eq!(
                    got.compressed,
                    compress_chunk(accept, chunk),
                    "chunk {position}"
                );
                offset += u64::try_from(chunk.len()).unwrap();
            }
            assert!(out.iter().any(|chunk| chunk.compressed.is_some()));
            assert!(out.iter().any(|chunk| chunk.compressed.is_none()));
        }

        /// On a runtime with a blocking pool every chunk compresses there,
        /// at most `depth` at once, and comes back in order and identical to
        /// sequential compression (br-asupersync-t1fblr.25).
        #[test]
        fn the_pipeline_compresses_on_the_blocking_pool_in_order() {
            let accept = session();
            let chunks = mixed_chunks();
            let input = chunks.clone();
            let runtime = crate::runtime::RuntimeBuilder::multi_thread()
                .build()
                .expect("runtime");
            let (out, pooled) = runtime.block_on(runtime.handle().spawn(async move {
                let cx = crate::cx::Cx::current().expect("task cx");
                run_pipeline(&cx, accept, 3, input).await
            }));
            assert_eq!(pooled, chunks.len(), "every chunk went to the pool");
            assert_sequential(&accept, &chunks, &out);
        }

        /// Without spawn authority (a test Cx) the pipeline compresses inline,
        /// with the same result.
        #[test]
        fn without_a_pool_the_pipeline_compresses_inline() {
            let accept = session();
            let chunks = mixed_chunks();
            let cx = crate::cx::Cx::for_testing();
            let (out, pooled) =
                crate::util::future::block_on(run_pipeline(&cx, accept, 3, chunks.clone()));
            assert_eq!(pooled, 0);
            assert_sequential(&accept, &chunks, &out);
        }

        /// Dropping a pipeline with jobs in flight detaches nothing: the
        /// region owns the jobs, so the runtime's teardown finishes within
        /// its bound once they retire.
        #[test]
        fn dropping_a_busy_pipeline_detaches_nothing() {
            let accept = session();
            let runtime = crate::runtime::RuntimeBuilder::multi_thread()
                .build()
                .expect("runtime");
            let pooled = runtime.block_on(runtime.handle().spawn(async move {
                let cx = crate::cx::Cx::current().expect("task cx");
                let mut entry = EntryCompression::new(CompressionMode::Zstd, "data.bin");
                let mut pipeline = ChunkPipeline::new(accept, 4);
                let text: Vec<u8> = b"asupersync transfer protocol "
                    .iter()
                    .copied()
                    .cycle()
                    .take(256 * 1024)
                    .collect();
                for index in 0..4_u64 {
                    pipeline.push(&cx, &mut entry, 0, index * 256 * 1024, text.clone());
                }
                let pooled = pipeline.pooled;
                drop(pipeline);
                pooled
            }));
            assert_eq!(pooled, 4);
            assert!(
                runtime.shutdown_timeout(std::time::Duration::from_secs(60)),
                "teardown waits out the dropped jobs and completes"
            );
        }

        #[test]
        fn incompressible_and_oversized_chunks_stay_raw() {
            let accept = session();
            let mut state = 7_u64;
            let noise: Vec<u8> = (0..4096)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    state.to_be_bytes()[0]
                })
                .collect();
            assert!(compress_chunk(&accept, &noise).is_none());
            assert!(compress_chunk(&accept, &vec![0; 256 * 1024 + 1]).is_none());
        }

        #[test]
        fn hostile_chunks_are_refused_before_allocation() {
            let accept = session();
            let (chunk, payload) = compress_chunk(&accept, &[0; 1000]).unwrap();
            let record = chunk.to_bytes();
            let mut out = Vec::new();
            assert_eq!(
                decompress_chunk(&record, None, 1000, &payload, &mut out),
                Err(ChunkCodecError::NotNegotiated)
            );
            assert_eq!(
                decompress_chunk(&[1, 1], Some(&accept), 1000, &payload, &mut out),
                Err(ChunkCodecError::CodecMismatch)
            );
            // The entry has fewer bytes left than the chunk declares.
            assert_eq!(
                decompress_chunk(&record, Some(&accept), 999, &payload, &mut out),
                Err(ChunkCodecError::TooLarge {
                    raw_len: 1000,
                    limit: 999
                })
            );
            // A declared length beyond the negotiated chunk limit.
            let huge = ChunkCodec::new(WireCodec::Zstd, u32::MAX).to_bytes();
            assert!(matches!(
                decompress_chunk(&huge, Some(&accept), u64::MAX, &payload, &mut out),
                Err(ChunkCodecError::TooLarge { .. })
            ));
            // A declared length that does not match the frame.
            let short = ChunkCodec::new(WireCodec::Zstd, 999).to_bytes();
            assert!(matches!(
                decompress_chunk(&short, Some(&accept), 1000, &payload, &mut out),
                Err(ChunkCodecError::Corrupt(_))
            ));
            // A payload that is not a zstd frame.
            let mut damaged = payload.clone();
            damaged[0] ^= 0xFF;
            assert!(matches!(
                decompress_chunk(&record, Some(&accept), 1000, &damaged, &mut out),
                Err(ChunkCodecError::Corrupt(_))
            ));
            // The untouched record still decodes.
            decompress_chunk(&record, Some(&accept), 1000, &payload, &mut out).unwrap();
            assert_eq!(out, vec![0; 1000]);
        }
    }
}
