//! Audit + regression test for `src/grpc/web.rs` metadata
//! ASCII-vs-binary encoding stability (tick #182).
//!
//! Operator's question: "verify ASCII-bin encoding stable."
//!
//! gRPC Spec context (PROTOCOL-HTTP2.md, Custom-Metadata-Value):
//!
//!   * **ASCII keys** (NOT ending in `-bin`): values are
//!     human-readable strings restricted to printable ASCII bytes
//!     (0x20-0x7E). Values containing other bytes are rejected.
//!   * **Binary keys** (ending in `-bin`): values are arbitrary
//!     bytes encoded as standard base64 (RFC 4648, padding
//!     `=`-character permitted).
//!   * The `-bin` suffix is the in-band signal — a peer that
//!     stores binary bytes under a non-`-bin` key is malformed.
//!
//! Audit findings:
//!
//!   (a) **Encode-side: binary values use STANDARD base64**
//!       (web.rs:153-155). `base64::engine::general_purpose::
//!       STANDARD.encode(...)` produces RFC 4648 base64 with
//!       padding. A regression to URL-safe base64 (different
//!       alphabet — `-_` instead of `+/`) would break interop
//!       with grpc-web.js / grpcurl which expect standard.
//!
//!   (b) **Decode-side: standard base64 with strict parse**
//!       (web.rs:248-258). Malformed base64 in a `-bin` trailer
//!       surfaces as `GrpcError::protocol("malformed base64 in
//!       -bin trailer metadata...")` (br-asupersync-ngnnc3).
//!       Pre-fix, a malformed base64 entry was silently elided
//!       while the rest of the trailer block accepted — a
//!       fail-closed change.
//!
//!   (c) **Round-trip stability** — bytes encoded then decoded
//!       through the trailer codec recover EXACTLY the original
//!       bytes. Includes high-bit bytes (0x80..0xFF) which would
//!       be mangled by an ASCII-only path.
//!
//!   (d) **`-bin` suffix routing**: `Metadata::insert_bin` adds
//!       the `-bin` suffix if missing (audited in tick #177).
//!       Round-trip pin: a value inserted as binary lands at a
//!       `-bin` key on the wire and decodes back to a Binary
//!       MetadataValue — never silently demoted to ASCII.
//!
//!   (e) **ASCII keys carry printable ASCII only** —
//!       `Metadata::insert` rejects values containing bytes outside
//!       0x20-0x7E. Rejecting the whole value avoids silently
//!       transmuting malformed data by concatenating its fragments.
//!
//!   (f) **`-bin` suffix and value type stay symmetric** — ASCII insertion
//!       rejects a `-bin` key, while `insert_bin` stores arbitrary bytes under
//!       that suffix. This prevents encode/decode type drift.
//!
//! Regression tests below pin (a)-(f) at the public API
//! surface.

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::grpc::Status;
use asupersync::grpc::streaming::{Metadata, MetadataValue};
use asupersync::grpc::web::{decode_trailers, encode_trailers};

const FRAME_HEADER_SIZE: usize = 5;

#[test]
fn binary_metadata_round_trips_through_trailer_codec() {
    // Pin (c): an arbitrary byte sequence (including high-bit
    // bytes that ASCII can't represent) round-trips exactly.
    let original_bytes: Vec<u8> = (0u8..=255u8).collect(); // every byte value
    let mut metadata = Metadata::new();
    assert!(metadata.insert_bin("trace-bin", Bytes::from(original_bytes.clone()),));

    let mut buf = BytesMut::new();
    encode_trailers(&Status::ok(), &metadata, &mut buf);

    let decoded =
        decode_trailers(&buf[FRAME_HEADER_SIZE..]).expect("trailers with -bin metadata decode");
    let recovered = decoded
        .metadata
        .get("trace-bin")
        .expect("trace-bin present after round-trip");
    match recovered {
        MetadataValue::Binary(b) => {
            assert_eq!(
                b.as_ref(),
                &original_bytes[..],
                "binary round-trip must preserve all 256 byte values exactly",
            );
        }
        MetadataValue::Ascii(s) => panic!("expected Binary value, got Ascii({s:?})"),
    }
}

#[test]
fn binary_metadata_uses_standard_base64_alphabet() {
    // Pin (a): the encoding uses RFC 4648 standard base64
    // (alphabet [A-Za-z0-9+/], padding =). A regression to
    // URL-safe base64 would use [A-Za-z0-9-_] and break
    // interop with grpc-web.js / grpcurl.
    //
    // We construct a payload whose standard base64 encoding
    // contains both `+` and `/` characters AND ends with `=`
    // padding — these are the differentiating chars. URL-safe
    // base64 would replace + with - and / with _.
    let payload = vec![0xFB, 0xFF, 0xBF]; // → "+/+/" pattern
    let mut metadata = Metadata::new();
    assert!(metadata.insert_bin("test-bin", Bytes::from(payload.clone())));

    let mut buf = BytesMut::new();
    encode_trailers(&Status::ok(), &metadata, &mut buf);
    let body = std::str::from_utf8(&buf[FRAME_HEADER_SIZE..]).expect("ascii body");

    // Find the test-bin: line and inspect the encoded value.
    let line = body
        .lines()
        .find(|line| line.starts_with("test-bin: "))
        .expect("test-bin trailer present");
    let encoded_value = line.strip_prefix("test-bin: ").expect("prefix");

    // Standard base64 of [0xFB, 0xFF, 0xBF] is "+/+/".
    assert_eq!(
        encoded_value, "+/+/",
        "standard base64 encoding (NOT URL-safe). URL-safe would \
         produce '-_-_'. got: {encoded_value:?}",
    );
}

#[test]
fn malformed_base64_in_bin_trailer_rejects_with_protocol_error() {
    // Pin (b): a peer that supplies invalid base64 in a `-bin`
    // metadata field gets a fail-closed `GrpcError::protocol`
    // rejection (br-asupersync-ngnnc3). Pre-fix the entry was
    // silently elided.
    let block = b"grpc-status: 0\r\nbad-bin: not-valid-base64!!\r\n";
    let result = decode_trailers(block);
    let err = result.expect_err("malformed base64 must reject");
    let err_str = format!("{err:?}");
    assert!(
        err_str.to_lowercase().contains("base64")
            || err_str.to_lowercase().contains("malformed")
            || err_str.to_lowercase().contains("protocol"),
        "rejection must mention base64 / malformed / protocol; got {err_str}",
    );
}

#[test]
fn ascii_metadata_does_not_get_base64_encoded() {
    // Pin (a)+(d): ASCII metadata (key NOT ending in -bin)
    // travels as the literal ASCII string, NOT base64-encoded.
    // A regression that base64-encoded all values would break
    // grep'ability of trailer blocks for operators.
    let mut metadata = Metadata::new();
    assert!(metadata.insert("x-trace-id", "abc-123"));

    let mut buf = BytesMut::new();
    encode_trailers(&Status::ok(), &metadata, &mut buf);
    let body = std::str::from_utf8(&buf[FRAME_HEADER_SIZE..]).expect("ascii body");

    assert!(
        body.contains("x-trace-id: abc-123\r\n"),
        "ASCII metadata travels as literal ASCII; got body: {body:?}",
    );
    // And NOT base64-encoded (the base64 of "abc-123" would be
    // "YWJjLTEyMw==").
    assert!(
        !body.contains("YWJjLTEyMw"),
        "ASCII metadata MUST NOT be base64-encoded",
    );
}

#[test]
fn empty_binary_value_round_trips() {
    // Pin (c) edge: an empty binary value encodes to empty
    // base64 and round-trips as empty. A regression that
    // produced a single padding char or refused to encode
    // empty would break interop.
    let mut metadata = Metadata::new();
    assert!(metadata.insert_bin("empty-bin", Bytes::new()));

    let mut buf = BytesMut::new();
    encode_trailers(&Status::ok(), &metadata, &mut buf);
    let decoded = decode_trailers(&buf[FRAME_HEADER_SIZE..]).expect("decode");
    match decoded.metadata.get("empty-bin") {
        Some(MetadataValue::Binary(b)) => assert_eq!(b.len(), 0),
        other => panic!("expected empty Binary, got {other:?}"),
    }
}

#[test]
fn binary_value_with_padding_round_trips() {
    // Pin (a)+(c): payloads whose base64 encoding requires
    // padding (`=` characters) round-trip cleanly. The decoder
    // must accept the padding correctly — a regression that
    // tightened to no-padding mode would reject standard
    // encodings.
    let cases = [
        vec![0x00],                   // 1 byte → "AA==" (2 pad chars)
        vec![0x00, 0x01],             // 2 bytes → "AAE=" (1 pad char)
        vec![0x00, 0x01, 0x02],       // 3 bytes → "AAEC" (no pad)
        vec![0x00, 0x01, 0x02, 0x03], // 4 bytes → "AAECAw==" (2 pad)
    ];
    for original in cases {
        let mut metadata = Metadata::new();
        assert!(metadata.insert_bin("round-trip-bin", Bytes::from(original.clone()),));
        let mut buf = BytesMut::new();
        encode_trailers(&Status::ok(), &metadata, &mut buf);
        let decoded = decode_trailers(&buf[FRAME_HEADER_SIZE..]).expect("decode");
        match decoded.metadata.get("round-trip-bin") {
            Some(MetadataValue::Binary(b)) => {
                assert_eq!(
                    b.as_ref(),
                    &original[..],
                    "round-trip must preserve {} bytes exactly",
                    original.len(),
                );
            }
            other => panic!("expected Binary, got {other:?}"),
        }
    }
}

#[test]
fn bin_suffix_routes_value_through_binary_path() {
    // Pin (d): a value inserted under a `-bin` key is treated
    // as binary on the wire and recovers as Binary on decode.
    // A regression that demoted to ASCII (and stripped non-
    // visible bytes) would silently corrupt binary data.
    let payload = vec![0x00, 0x7F, 0x80, 0xFF]; // mix of ASCII + non-ASCII
    let mut metadata = Metadata::new();
    assert!(metadata.insert_bin("route-bin", Bytes::from(payload.clone())));

    let mut buf = BytesMut::new();
    encode_trailers(&Status::ok(), &metadata, &mut buf);
    let decoded = decode_trailers(&buf[FRAME_HEADER_SIZE..]).expect("decode");
    let value = decoded
        .metadata
        .get("route-bin")
        .expect("route-bin present");
    match value {
        MetadataValue::Binary(b) => {
            assert_eq!(b.as_ref(), &payload[..]);
        }
        MetadataValue::Ascii(_) => {
            panic!("-bin key value MUST decode as Binary, never demoted to Ascii");
        }
    }
}

#[test]
fn ascii_value_with_high_bit_bytes_rejected_at_insert() {
    // Pin (e): a peer that puts non-ASCII bytes into an ASCII
    // (non-`-bin`) value has the entire value rejected.
    let mut metadata = Metadata::new();
    let value_with_high_bit: String = (32u8..255u8).map(char::from).collect();
    assert!(!metadata.insert("x-mixed", value_with_high_bit));
    assert!(metadata.get("x-mixed").is_none());
}

#[test]
fn ascii_value_under_bin_suffix_is_rejected_without_replacing_binary_value() {
    let mut metadata = Metadata::new();
    assert!(metadata.insert_bin("trace-bin", Bytes::from_static(b"binary")));
    assert!(!metadata.insert("other-bin", "YmFzZTY0"));
    assert!(!metadata.insert_or_replace("trace-bin", "YmFzZTY0"));
    assert!(metadata.get("other-bin").is_none());
    assert!(matches!(
        metadata.get("trace-bin"),
        Some(MetadataValue::Binary(value)) if value.as_ref() == b"binary"
    ));
}
