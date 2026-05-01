//! Audit + regression test for `src/grpc/web.rs`
//! `Base64StreamDecoder` chunked-input handling (tick #207).
//!
//! Operator's question: "verify request body upload chunked
//! encoding parser." gRPC over HTTP/2 uses DATA frames (no
//! chunked transfer encoding); the chunked-input surface in
//! the gRPC subsystem is the gRPC-Web text-mode streaming
//! base64 decoder, which handles HTTP/1.1 chunked body
//! delivery (each chunk possibly mid-base64-quartet).
//!
//! Audit findings:
//!
//!   (a) **Mid-quartet split-points are SAFE** — chunk
//!       boundaries that fall mid-base64-quartet are buffered
//!       across `push` calls (0-3 byte partial-quartet
//!       residue). A regression that lost residue between
//!       chunks would corrupt the decoded bytes.
//!
//!   (b) **Padding seals the decoder** — observing `=` in any
//!       chunk treats that chunk as the FINAL one. Subsequent
//!       `push` calls reject with `Status::protocol("...
//!       sealed ...")`.
//!
//!   (c) **`finish()` decodes unpadded tail** — STANDARD_NO_PAD
//!       decodes 2-3 char tails. A single trailing char is
//!       invalid base64 and surfaces as Err.
//!
//!   (d) **Sealed decoder rejects further push** — the
//!       sealed-state check fires BEFORE any decode work, so
//!       a peer that tries to push more data after padding
//!       gets a clear error.
//!
//!   (e) **Empty chunk is no-op** — `push(&[])` returns empty
//!       Vec without state mutation. Useful for adapters that
//!       call push on every HTTP body delivery including
//!       empty CONTINUATION frames.
//!
//!   (f) **Malformed base64 rejects with protocol error** —
//!       a chunk containing non-base64 bytes (e.g. `*`, `<`)
//!       surfaces as `GrpcError::protocol(...)`. The error
//!       message references the bead `br-asupersync-37svtb`.
//!
//!   (g) **No memory amplification** — buffered residue is at
//!       most 3 bytes per decoder. A peer cannot grow the
//!       per-decoder state arbitrarily.
//!
//! Regression tests below pin (a)-(g).

use asupersync::grpc::web::Base64StreamDecoder;

#[test]
fn chunked_decode_round_trips_payload_split_at_quartet_boundary() {
    // Pin (a): split base64 input AT a quartet boundary
    // (4-byte aligned). Each chunk is a complete quartet.
    let original = b"Hello, gRPC-Web!";
    let encoded = base64_encode(original);
    let half = encoded.len() / 2;
    // Round half down to nearest multiple of 4 to land on
    // quartet boundary.
    let split = (half / 4) * 4;
    let (chunk1, chunk2) = encoded.split_at(split);

    let mut decoder = Base64StreamDecoder::new();
    let mut decoded = decoder.push(chunk1.as_bytes()).expect("chunk 1");
    decoded.extend(decoder.push(chunk2.as_bytes()).expect("chunk 2"));
    decoded.extend(decoder.finish().expect("finish"));

    assert_eq!(
        decoded.as_slice(),
        original,
        "quartet-aligned split produces the exact original bytes",
    );
}

#[test]
fn chunked_decode_round_trips_payload_split_mid_quartet() {
    // Pin (a) audit-critical: split MID-quartet (e.g. at
    // offset 5 — 1 byte into the second quartet). The decoder
    // must buffer the 1-byte residue and combine it with
    // chunk2's start.
    let original = b"chunked midquartet test";
    let encoded = base64_encode(original);
    // Try every possible split point within the first 12
    // chars to exercise residue lengths 0, 1, 2, 3.
    for split in 1..encoded.len().min(20) {
        let (chunk1, chunk2) = encoded.split_at(split);
        let mut decoder = Base64StreamDecoder::new();
        let mut decoded = decoder.push(chunk1.as_bytes()).expect("chunk 1");
        decoded.extend(decoder.push(chunk2.as_bytes()).expect("chunk 2"));
        decoded.extend(decoder.finish().expect("finish"));

        assert_eq!(
            decoded.as_slice(),
            original,
            "mid-quartet split at offset {split} must round-trip",
        );
    }
}

#[test]
fn chunked_decode_preserves_payload_across_many_small_chunks() {
    // Pin (a) extreme: 1-char-at-a-time chunks. Every push
    // adds 1 byte to the residue; only every 4 pushes produce
    // a complete quartet to decode. A regression that lost
    // residue would corrupt every multi-byte payload.
    let original = b"single char chunks per push";
    let encoded = base64_encode(original);

    let mut decoder = Base64StreamDecoder::new();
    let mut decoded = Vec::new();
    for ch in encoded.bytes() {
        decoded.extend(decoder.push(&[ch]).expect("push 1 char"));
    }
    decoded.extend(decoder.finish().expect("finish"));

    assert_eq!(decoded.as_slice(), original);
}

#[test]
fn padding_in_chunk_seals_decoder() {
    // Pin (b): observing `=` in any chunk treats that chunk
    // as the FINAL one and seals the decoder.
    let original = b"a"; // → "YQ==" (2 padding chars)
    let encoded = base64_encode(original);
    assert!(encoded.contains('='), "test fixture has padding");

    let mut decoder = Base64StreamDecoder::new();
    assert!(!decoder.is_sealed());
    let decoded = decoder.push(encoded.as_bytes()).expect("decode");
    assert_eq!(decoded.as_slice(), original);
    assert!(
        decoder.is_sealed(),
        "decoder MUST be sealed after observing padding",
    );
}

#[test]
fn sealed_decoder_rejects_subsequent_push() {
    // Pin (b)+(d): post-seal push rejects with protocol error.
    let mut decoder = Base64StreamDecoder::new();
    let _ = decoder.push(b"YQ==").expect("first push with padding seals");

    let err = decoder
        .push(b"more")
        .expect_err("post-seal push must reject");
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("sealed") || err_str.contains("protocol"),
        "post-seal rejection mentions seal/protocol; got {err_str}",
    );
}

#[test]
fn finish_decodes_unpadded_two_three_char_tail() {
    // Pin (c): STANDARD_NO_PAD permits 2 or 3 char tails on
    // finish (the binary length is independently known via
    // content-length / chunked terminator).
    let original = b"hi"; // → "aGk" (3 chars, no padding)
    let encoded = base64_encode_no_pad(original);
    assert_eq!(encoded.len() % 4, 3);

    let mut decoder = Base64StreamDecoder::new();
    let _ = decoder.push(encoded.as_bytes()).expect("partial push");
    let tail = decoder.finish().expect("finish decodes 3-char tail");
    assert_eq!(tail.as_slice(), original);
}

#[test]
fn finish_with_one_char_tail_rejects() {
    // Pin (c) edge: a 1-char tail is invalid base64 — finish
    // surfaces Err.
    let mut decoder = Base64StreamDecoder::new();
    let _ = decoder.push(b"A").expect("push 1 char (residue)");
    let err = decoder
        .finish()
        .expect_err("1-char tail is invalid base64");
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("invalid") || err_str.contains("base64"),
        "1-char tail rejection mentions invalid/base64; got {err_str}",
    );
}

#[test]
fn empty_chunk_push_is_no_op() {
    // Pin (e): empty chunk returns empty Vec without mutating
    // state.
    let mut decoder = Base64StreamDecoder::new();
    let result = decoder.push(&[]).expect("empty push OK");
    assert!(result.is_empty());
    assert!(!decoder.is_sealed());
    // Subsequent legitimate push still works.
    let _ = decoder.push(b"YWJj").expect("real push works after empty");
}

#[test]
fn malformed_base64_chunk_rejects_with_protocol_error() {
    // Pin (f): chunk containing non-base64 bytes rejects.
    let mut decoder = Base64StreamDecoder::new();
    let err = decoder
        .push(b"abcd*invalid")
        .expect_err("non-base64 byte rejects");
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("invalid")
            || err_str.contains("base64")
            || err_str.contains("protocol"),
        "malformed-base64 rejection class is protocol; got {err_str}",
    );
}

#[test]
fn decoder_residue_bounded_at_three_bytes() {
    // Pin (g): the buffered residue is at most 3 bytes per
    // decoder regardless of how much input is pushed. A
    // regression that grew the residue unboundedly would be
    // a memory amplification vector.
    //
    // We pin behaviorally: pushing many complete quartets
    // doesn't accumulate residue. After every complete-
    // quartet push, the decoder's internal state is at the
    // same level (residue cleared).
    let mut decoder = Base64StreamDecoder::new();
    for _ in 0..1000 {
        // 4 base64 chars = 1 complete quartet, no residue.
        let _ = decoder.push(b"YWJj").expect("complete quartet push");
    }
    // No way to directly inspect residue length, but we can
    // pin via finish — finish on a residue-free decoder
    // succeeds with an empty Vec.
    let tail = decoder.finish().expect("finish succeeds");
    assert!(
        tail.is_empty(),
        "1000 complete quartets leave NO residue at finish",
    );
}

#[test]
fn padding_with_extra_bytes_after_rejects() {
    // Pin (b) strictness: the STANDARD validator rejects
    // padding followed by non-padding bytes (e.g. "Y===Q").
    // A peer that crafts such input cannot smuggle past the
    // padding-seals check.
    let mut decoder = Base64StreamDecoder::new();
    let err = decoder
        .push(b"YQ==EXTRA")
        .expect_err("padding + extra bytes is invalid");
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("invalid") || err_str.contains("base64"),
        "post-padding extra bytes rejection class: {err_str}",
    );
}

#[test]
fn decoder_default_is_unsealed() {
    // Pin: a fresh decoder is NOT sealed. The seal flag flips
    // only on explicit padding observation or finish() call.
    let decoder = Base64StreamDecoder::default();
    assert!(!decoder.is_sealed());
    let decoder = Base64StreamDecoder::new();
    assert!(!decoder.is_sealed());
}

#[test]
fn finish_on_empty_decoder_is_no_op() {
    // Pin (c) edge: finish on a never-pushed decoder returns
    // empty Vec.
    let mut decoder = Base64StreamDecoder::new();
    let tail = decoder.finish().expect("finish on empty decoder");
    assert!(tail.is_empty());
}

// ── Helpers ──────────────────────────────────────────

fn base64_encode(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input)
}

fn base64_encode_no_pad(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(input)
}
