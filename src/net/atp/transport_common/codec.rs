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
        CompressionMode::Zstd => {
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
    let params = asupersync_zstd::EncodeParams {
        checksum: false,
        ..asupersync_zstd::EncodeParams::new(asupersync_zstd::Level::Fast)
    };
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
    let limits = asupersync_zstd::DecodeLimits {
        max_window: 1_usize
            .checked_shl(u32::from(accept.max_window_log))
            .unwrap_or(0),
        require_content_size: true,
        allow_skippable_frames: false,
        ..asupersync_zstd::DecodeLimits::new(raw_len)
    };
    out.clear();
    out.resize(raw_len, 0);
    let written = asupersync_zstd::decode_into(payload, out, &limits)
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
