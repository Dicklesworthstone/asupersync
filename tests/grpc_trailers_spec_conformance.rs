//! Conformance harness: gRPC-Web trailer-block byte format vs the
//! gRPC-Web specification (the same one tonic-web implements).
//!
//! For gRPC over HTTP/2, trailers are HPACK-encoded HTTP/2 trailers
//! whose pre-HPACK key/value pairs are spec-defined. For gRPC-Web
//! (HTTP/1.1 fallback), trailers are an HTTP/1.1-shaped header block
//! prefixed with the `0x80` flag byte and a 4-byte big-endian length.
//! gRPC-Web's encoding is HPACK-free, so it IS byte-stable — and
//! that's the layer this file pins. The test asserts that
//! `asupersync::grpc::encode_trailers` produces wire bytes
//! byte-identical to a manual spec oracle for several (Status,
//! Metadata) fixtures. Since tonic-web implements the same spec, a
//! pass here transitively means tonic-web peers see the same bytes.
//!
//! Spec-pinned rules:
//!   * Trailer flag byte is `0x80`.
//!   * 4-byte big-endian length of the header block follows the flag.
//!   * `grpc-status: <decimal>\r\n` (always present, even for OK=0).
//!   * `grpc-message: <percent-encoded>\r\n` only when the message
//!     is non-empty. `%`, `\r`, `\n` are percent-encoded as `%25`,
//!     `%0D`, `%0A` respectively (gRPC spec — defends against
//!     trailer injection).
//!   * Custom metadata: lowercased key, `<key>: <value>\r\n`.
//!     Binary keys end with `-bin` and the value is base64.
//!   * Iteration order is insertion order (HTTP/1.1 trailers are
//!     ordered).
//!
//! Out of scope (separate beads):
//!   * HTTP/2 trailer HPACK byte equivalence — encoder-state-dependent;
//!     the relevant logical-pair conformance lives elsewhere.
//!   * Trailer DECODING — covered by `tests/conformance/grpc_web_frame_format.rs`.

use asupersync::bytes::BytesMut;
use asupersync::grpc::{Code, Metadata, Status, encode_trailers};

const TRAILER_FLAG: u8 = 0x80;

/// Builds the canonical spec-oracle bytes for a (Status, Metadata)
/// pair. This is a faithful reading of the gRPC-Web trailer spec
/// without going through the asupersync encoder.
fn oracle_trailer_bytes(status: &Status, ordered_pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut block = String::new();

    block.push_str("grpc-status: ");
    block.push_str(&status.code().as_i32().to_string());
    block.push_str("\r\n");

    if !status.message().is_empty() {
        block.push_str("grpc-message: ");
        let escaped = status
            .message()
            .replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A");
        block.push_str(&escaped);
        block.push_str("\r\n");
    }

    for &(key, value) in ordered_pairs {
        // Spec: keys must be ascii-lowercase; the encoder normalizes
        // for us, so the oracle takes already-lowercase keys.
        block.push_str(key);
        block.push_str(": ");
        block.push_str(value);
        block.push_str("\r\n");
    }

    let block_bytes = block.into_bytes();
    let mut out = Vec::with_capacity(5 + block_bytes.len());
    out.push(TRAILER_FLAG);
    out.extend_from_slice(&u32::try_from(block_bytes.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&block_bytes);
    out
}

#[test]
fn trailers_ok_with_no_metadata_match_spec_oracle() {
    let status = Status::new(Code::Ok, "");
    let metadata = Metadata::new();

    let mut wire = BytesMut::new();
    encode_trailers(&status, &metadata, &mut wire);
    let oracle = oracle_trailer_bytes(&status, &[]);

    assert_eq!(
        wire.as_ref(),
        oracle.as_slice(),
        "Code::Ok with empty message and no metadata must produce the canonical \
         minimal trailer block: flag + length + 'grpc-status: 0\\r\\n'",
    );
}

#[test]
fn trailers_error_with_message_percent_encodes_per_spec() {
    let status = Status::new(Code::Internal, "boom\r\nwith %newline");
    let metadata = Metadata::new();

    let mut wire = BytesMut::new();
    encode_trailers(&status, &metadata, &mut wire);
    let oracle = oracle_trailer_bytes(&status, &[]);

    assert_eq!(
        wire.as_ref(),
        oracle.as_slice(),
        "grpc-message must percent-encode '%' / '\\r' / '\\n' as '%25' / '%0D' / '%0A' — \
         spec defense against trailer injection",
    );

    // Sanity: the oracle actually contains the encoded sequences.
    let oracle_text = std::str::from_utf8(&oracle[5..]).expect("ascii block is valid utf8");
    assert!(
        oracle_text.contains("boom%0D%0Awith %25newline"),
        "oracle must contain percent-encoded message; got block:\n{oracle_text}",
    );
}

#[test]
fn trailers_with_custom_ascii_metadata_preserve_insertion_order() {
    let status = Status::new(Code::Unauthenticated, "auth required");
    let mut metadata = Metadata::new();
    assert!(metadata.insert("x-trace-id", "abc123"));
    assert!(metadata.insert("x-tenant", "acme-corp"));

    let mut wire = BytesMut::new();
    encode_trailers(&status, &metadata, &mut wire);

    // Oracle: status, message, then custom keys in insertion order
    // with lowercase keys (encoder normalises, oracle uses already-
    // lowercased).
    let oracle = oracle_trailer_bytes(
        &status,
        &[("x-trace-id", "abc123"), ("x-tenant", "acme-corp")],
    );

    assert_eq!(
        wire.as_ref(),
        oracle.as_slice(),
        "custom ASCII trailing metadata must follow grpc-status/grpc-message in \
         insertion order, with lowercased keys",
    );
}

#[test]
fn trailers_with_binary_metadata_base64_encode_value() {
    use base64::Engine;
    let status = Status::new(Code::Ok, "");
    let mut metadata = Metadata::new();
    let raw_bytes: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
    assert!(metadata.insert_bin(
        "x-binary-bin",
        asupersync::bytes::Bytes::copy_from_slice(raw_bytes),
    ));

    let mut wire = BytesMut::new();
    encode_trailers(&status, &metadata, &mut wire);

    let expected_b64 = base64::engine::general_purpose::STANDARD.encode(raw_bytes);
    let oracle = oracle_trailer_bytes(&status, &[("x-binary-bin", expected_b64.as_str())]);

    assert_eq!(
        wire.as_ref(),
        oracle.as_slice(),
        "binary trailing metadata must be base64-encoded with the standard \
         alphabet; the same encoding tonic-web uses for tonic::metadata::BinaryMetadataValue",
    );
}

#[test]
fn trailers_dedupe_status_and_message_when_user_supplies_them_in_metadata() {
    // Defensive: a caller supplies a Metadata that already contains
    // grpc-status / grpc-message. Spec says: the encoded block has
    // EXACTLY ONE grpc-status. asupersync's encoder filters duplicates
    // out (web.rs lines 144-147). The oracle below assumes filtering;
    // a regression that allowed double emission would be a protocol
    // attack vector (br-asupersync-nbryje on the decoder side).
    let status = Status::new(Code::Ok, "");
    let mut metadata = Metadata::new();
    // These must be IGNORED by the encoder.
    assert!(metadata.insert("grpc-status", "999"));
    assert!(metadata.insert("grpc-message", "fake"));
    // This should pass through.
    assert!(metadata.insert("x-keep", "real"));

    let mut wire = BytesMut::new();
    encode_trailers(&status, &metadata, &mut wire);

    let oracle = oracle_trailer_bytes(&status, &[("x-keep", "real")]);
    assert_eq!(
        wire.as_ref(),
        oracle.as_slice(),
        "encoder must NOT emit a second grpc-status/grpc-message even if the \
         caller smuggled them via Metadata — a duplicate would let an attacker \
         mask a real failure status with a synthetic 'grpc-status: 0' append",
    );
}

#[test]
fn trailers_frame_layout_flag_and_length_are_canonical() {
    // Strict byte-by-byte assertions on the prefix shape so a future
    // regression that flips endianness or drops the flag bit
    // surfaces with a clear message.
    let status = Status::new(Code::FailedPrecondition, "x");
    let metadata = Metadata::new();
    let mut wire = BytesMut::new();
    encode_trailers(&status, &metadata, &mut wire);

    assert!(
        wire.len() >= 5,
        "trailer frame must include the 5-byte prefix",
    );
    assert_eq!(
        wire[0], TRAILER_FLAG,
        "first byte must be the trailer flag 0x80 — distinguishes trailers from data",
    );
    let declared = u32::from_be_bytes([wire[1], wire[2], wire[3], wire[4]]) as usize;
    assert_eq!(
        declared,
        wire.len() - 5,
        "BE u32 length prefix must equal the block length (no padding, no truncation)",
    );
}
