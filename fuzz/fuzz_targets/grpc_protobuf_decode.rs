//! Adversarial wire-byte fuzz target for `asupersync::grpc::protobuf`.
//!
//! Complements `grpc_prost_codec_decode.rs` by focusing on raw bytes rather
//! than structured message-builder coverage. Each iteration constructs a
//! fragment from primitive parts the protobuf wire format permits and pumps
//! it through `ProstCodec::decode`, asserting:
//!
//!   1. No panic. Every input must surface a typed [`ProtobufError`] (or
//!      `Ok`) — never an unwind from the codec or prost.
//!   2. Returned errors are well-typed. Every error branch is one of
//!      `EncodeError`, `DecodeError`, `MessageTooLarge`.
//!   3. Memory bounded by the codec's `max_message_size`. The harness pins
//!      the limit and refuses inputs that would request more than the cap.
//!
//! Coverage targets called out in br-asupersync-3psbie:
//!   - Varint overflow (10+ continuation bytes with high-bit set).
//!   - Unknown fields (tags outside the defined schema).
//!   - Deeply nested messages (length-prefixed sub-messages dozens deep).
//!   - Malformed length-prefixes (length > remaining bytes).
//!   - Integer truncation (i32 fields fed wire-encoded u64s with high bits).
//!
//! Run with:
//!
//! ```bash
//! rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_pane7 \
//!     cargo +nightly fuzz run grpc_protobuf_decode -- -max_total_time=180
//! ```

#![no_main]

use asupersync::bytes::Bytes;
use asupersync::grpc::Codec;
use asupersync::grpc::protobuf::{ProstCodec, ProtobufError};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 16 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_FIELDS: usize = 64;
const MAX_STRING_LEN: usize = 1024;
const MAX_BYTES_LEN: usize = 1024;
const CODEC_MAX_MESSAGE_SIZE: usize = 32 * 1024;

/// Top-level message exercising the broadest schema: nested messages with
/// repeated fields, every scalar wire type, plus `unknown_fields`-style
/// gaps in the tag space (tags 7–9 are deliberately omitted in the schema
/// so unknown-field paths get hit by tags 7..=9 in synthesized wire bytes).
#[derive(Clone, PartialEq, prost::Message)]
struct OuterMessage {
    #[prost(int64, tag = "1")]
    seq: i64,
    #[prost(string, tag = "2")]
    label: String,
    #[prost(message, optional, tag = "3")]
    inner: Option<InnerMessage>,
    #[prost(message, repeated, tag = "4")]
    children: Vec<InnerMessage>,
    #[prost(bytes = "vec", tag = "5")]
    payload: Vec<u8>,
    #[prost(uint32, tag = "10")]
    flags: u32,
    #[prost(int32, tag = "11")]
    truncatable: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct InnerMessage {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(int32, tag = "2")]
    value: i32,
    #[prost(message, optional, boxed, tag = "3")]
    next: Option<Box<InnerMessage>>,
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_LEN {
        return;
    }

    let mut cursor = Cursor::new(data);
    let strategy = cursor.next_u8() % 5;

    let wire = match strategy {
        0 => cursor.synthetic_varint_storm(),
        1 => cursor.synthetic_unknown_fields(),
        2 => cursor.synthetic_deep_nesting(),
        3 => cursor.synthetic_truncated_lengths(),
        _ => cursor.synthetic_mixed(),
    };

    if wire.len() > MAX_INPUT_LEN {
        return;
    }

    let mut codec: ProstCodec<OuterMessage, OuterMessage> =
        ProstCodec::with_max_size(CODEC_MAX_MESSAGE_SIZE);
    let buf = Bytes::from(wire);

    match codec.decode(&buf) {
        Ok(msg) => {
            // On success the decoder must not have produced something
            // larger than the configured limit.
            let encoded_len = prost::Message::encoded_len(&msg);
            assert!(
                encoded_len <= CODEC_MAX_MESSAGE_SIZE,
                "decoded message exceeds codec max_message_size: {encoded_len} > {}",
                CODEC_MAX_MESSAGE_SIZE
            );
        }
        Err(e) => match e {
            ProtobufError::EncodeError(_)
            | ProtobufError::DecodeError(_)
            | ProtobufError::MessageTooLarge { .. } => {
                // Expected: typed error.
            }
        },
    }
});

/// Wire-format primitives. These mirror prost's `prost::encoding` helpers
/// but avoid the public-API constraint by emitting bytes directly.
mod wire {
    /// Wire types per protobuf encoding spec.
    pub const WT_VARINT: u8 = 0;
    pub const WT_FIXED64: u8 = 1;
    pub const WT_LEN_DELIM: u8 = 2;
    pub const WT_FIXED32: u8 = 5;

    pub fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            buf.push((value as u8) | 0x80);
            value >>= 7;
        }
        buf.push(value as u8);
    }

    pub fn write_tag(buf: &mut Vec<u8>, field: u32, wire_type: u8) {
        let header = (u64::from(field) << 3) | u64::from(wire_type);
        write_varint(buf, header);
    }

    pub fn write_len_delim(buf: &mut Vec<u8>, field: u32, payload: &[u8]) {
        write_tag(buf, field, WT_LEN_DELIM);
        write_varint(buf, payload.len() as u64);
        buf.extend_from_slice(payload);
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    prng: u64,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        let mut seed = 0xdead_beef_cafe_babeu64;
        for (i, &b) in data.iter().take(16).enumerate() {
            seed ^= u64::from(b).wrapping_shl((i % 8) as u32 * 8);
        }
        Self {
            data,
            pos: 0,
            prng: seed.max(1),
        }
    }

    fn xorshift(&mut self) -> u64 {
        let mut x = self.prng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.prng = x;
        x
    }

    fn next_u8(&mut self) -> u8 {
        if self.pos < self.data.len() {
            let b = self.data[self.pos];
            self.pos += 1;
            b
        } else {
            (self.xorshift() & 0xFF) as u8
        }
    }

    fn next_u16(&mut self) -> u16 {
        u16::from(self.next_u8()) | (u16::from(self.next_u8()) << 8)
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        let avail = self.data.len().saturating_sub(self.pos).min(n);
        if avail > 0 {
            out.extend_from_slice(&self.data[self.pos..self.pos + avail]);
            self.pos += avail;
        }
        while out.len() < n {
            let r = self.xorshift().to_le_bytes();
            let want = (n - out.len()).min(8);
            out.extend_from_slice(&r[..want]);
        }
        out
    }

    /// Strategy 0: emit a tag with WT_VARINT then a long run of 0x80 bytes
    /// followed by an arbitrary terminator byte. Targets the varint
    /// overflow guard in the prost decoder.
    fn synthetic_varint_storm(&mut self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        // Pick a real field tag so the dispatch reaches an int field, then
        // start its value with 11+ continuation bytes (>10 is illegal per
        // the spec — varints fit in 10 bytes for u64).
        let tag = match self.next_u8() % 5 {
            0 => 1,                            // seq (i64) — main offender for u64 truncation
            1 => 10,                           // flags (u32)
            2 => 11,                           // truncatable (i32)
            3 => 1000 + self.next_u8() as u32, // unknown high tag
            _ => self.next_u16() as u32,
        };
        wire::write_tag(&mut buf, tag, wire::WT_VARINT);
        let burst = (self.next_u8() % 24) as usize + 1;
        for _ in 0..burst {
            buf.push(0x80);
        }
        buf.push(self.next_u8());
        // Sometimes append a second valid tag/value to test recovery
        // semantics after a malformed prefix.
        if self.next_u8() & 1 == 0 {
            wire::write_tag(&mut buf, 2, wire::WT_LEN_DELIM);
            wire::write_varint(&mut buf, 4);
            buf.extend_from_slice(b"abcd");
        }
        buf
    }

    /// Strategy 1: emit a sequence of tags outside the schema's known field
    /// numbers so the decoder exercises its unknown-field-skip path.
    fn synthetic_unknown_fields(&mut self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        let count = (self.next_u8() % MAX_FIELDS as u8) as usize;
        for _ in 0..count {
            // Tags 7, 8, 9 are unused in OuterMessage; tags > 11 are
            // unknown. Mix both classes plus occasional reserved-style
            // tags (tag 0 is invalid per the spec).
            let tag = match self.next_u8() % 6 {
                0 => 0,                                // invalid: tag 0
                1 => 7,                                // gap in schema
                2 => 8,                                // gap in schema
                3 => 9,                                // gap in schema
                4 => 12 + (self.next_u16() as u32 % 1024), // beyond schema
                _ => 1 << 28,                          // huge tag
            };
            let wire_type = self.next_u8() % 6; // 6+ are reserved/illegal
            wire::write_tag(&mut buf, tag, wire_type);
            match wire_type {
                wire::WT_VARINT => wire::write_varint(&mut buf, self.xorshift()),
                wire::WT_FIXED64 => buf.extend_from_slice(&self.xorshift().to_le_bytes()),
                wire::WT_LEN_DELIM => {
                    let payload_len = (self.next_u16() as usize) % 32;
                    wire::write_varint(&mut buf, payload_len as u64);
                    buf.extend_from_slice(&self.take(payload_len));
                }
                wire::WT_FIXED32 => {
                    let v = self.xorshift() as u32;
                    buf.extend_from_slice(&v.to_le_bytes());
                }
                _ => {
                    // Reserved/unknown wire types — push raw garbage for
                    // the rest of the budget so the decoder must reject.
                }
            }
            if buf.len() > MAX_INPUT_LEN / 2 {
                break;
            }
        }
        buf
    }

    /// Strategy 2: build a nested-message tower. Tag 3 of OuterMessage is
    /// `inner: Option<InnerMessage>` and InnerMessage::next is also
    /// optional+boxed, so length-delimited frames can stack arbitrarily
    /// deep until the decoder either rejects or recurses.
    fn synthetic_deep_nesting(&mut self) -> Vec<u8> {
        let depth = (self.next_u8() as usize) % MAX_DEPTH + 1;
        // Build inside-out: innermost message first.
        let mut inner = Vec::new();
        wire::write_len_delim(&mut inner, 1, b"leaf");
        wire::write_tag(&mut inner, 2, wire::WT_VARINT);
        wire::write_varint(&mut inner, u64::from(self.next_u16()));

        for _ in 0..depth {
            let mut next = Vec::new();
            wire::write_len_delim(&mut next, 3, &inner); // nest into next
            inner = next;
            if inner.len() > MAX_INPUT_LEN / 2 {
                break;
            }
        }

        // Wrap one more time as the OuterMessage.inner field (tag 3).
        let mut outer = Vec::new();
        wire::write_len_delim(&mut outer, 3, &inner);
        outer
    }

    /// Strategy 3: emit length-prefixed fields whose stated length is
    /// larger than what's actually present, exercising the
    /// out-of-bounds-prefix guard.
    fn synthetic_truncated_lengths(&mut self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        let target_field = match self.next_u8() % 4 {
            0 => 2, // label (string)
            1 => 4, // children (repeated InnerMessage)
            2 => 5, // payload (bytes)
            _ => 3, // inner (single InnerMessage)
        };
        wire::write_tag(&mut buf, target_field, wire::WT_LEN_DELIM);
        // Stated length is far larger than what's actually present.
        let advertised = match self.next_u8() % 4 {
            0 => u32::MAX as u64,
            1 => CODEC_MAX_MESSAGE_SIZE as u64 * 2,
            2 => MAX_INPUT_LEN as u64 * 4,
            _ => self.xorshift(),
        };
        wire::write_varint(&mut buf, advertised);
        // Provide a small actual payload so the decoder must detect the
        // lie rather than read past EOF.
        let actual_len = (self.next_u16() as usize) % MAX_STRING_LEN.min(64);
        buf.extend_from_slice(&self.take(actual_len));
        buf
    }

    /// Strategy 4: synthesize a valid-looking OuterMessage by directly
    /// emitting wire-encoded fields, but with adversarial-leaning values.
    /// Drives the happy decode path AND the truncation path for i32 fed
    /// from u64 wire varints.
    fn synthetic_mixed(&mut self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        // seq (int64)
        wire::write_tag(&mut buf, 1, wire::WT_VARINT);
        wire::write_varint(&mut buf, self.xorshift());
        // label (string)
        let label_len = (self.next_u8() as usize) % MAX_STRING_LEN.min(96);
        let label = self.take(label_len);
        wire::write_len_delim(&mut buf, 2, &label);
        // payload (bytes)
        let payload_len = (self.next_u16() as usize) % MAX_BYTES_LEN.min(512);
        let payload = self.take(payload_len);
        wire::write_len_delim(&mut buf, 5, &payload);
        // flags (uint32)
        wire::write_tag(&mut buf, 10, wire::WT_VARINT);
        wire::write_varint(&mut buf, self.xorshift());
        // truncatable (int32) — feed full u64 to test integer-truncation
        // path (prost decodes via varint and casts).
        wire::write_tag(&mut buf, 11, wire::WT_VARINT);
        wire::write_varint(&mut buf, self.xorshift());
        // Optional nested inner.
        if self.next_u8() & 1 == 0 {
            let mut inner = Vec::new();
            wire::write_len_delim(&mut inner, 1, b"inner");
            wire::write_tag(&mut inner, 2, wire::WT_VARINT);
            wire::write_varint(&mut inner, self.xorshift());
            wire::write_len_delim(&mut buf, 3, &inner);
        }
        buf
    }
}
