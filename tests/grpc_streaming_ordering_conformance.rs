//! Conformance harness: server-streaming wire-byte ordering preserved
//! through asupersync's frame+codec layer.
//!
//! Pins the invariant that a sequence of N gRPC messages encoded back-
//! to-back into a single buffer (the way an HTTP/2 server-streaming
//! body lands on the wire) decodes back to the EXACT same sequence in
//! the SAME order. This is the same contract `tonic` provides on top
//! of `tower-http` + `prost` + `h2` — a divergence would mean a client
//! interoperating with a tonic server would observe re-ordered or
//! duplicated messages.
//!
//! Why this is enough to call "vs tonic": the gRPC wire format
//! (Length-Prefixed Message: 1-byte compressed flag + 4-byte
//! big-endian length + N-byte payload) is identical across
//! implementations. Tonic and asupersync both use prost for the
//! payload encode/decode and the same LPM framing. If our
//! `FramedCodec<ProstCodec<T, T>>` round-trip preserves order for a
//! 100-message sequence, a tonic peer reading the same wire bytes
//! observes the same order — that's the conformance guarantee, not
//! a symbol-by-symbol comparison against tonic's call graph.
//!
//! What this file does NOT cover (out of scope, separate beads):
//!   * HTTP/2 flow-control / WINDOW_UPDATE behavior — pinned by the
//!     existing h2_* fuzz / metamorphic tests.
//!   * Stream cancellation propagation — `tests/grpc_*_cancellation.rs`.
//!   * Per-message metadata trailers — separate codec contract.

use asupersync::bytes::BytesMut;
use asupersync::grpc::{FramedCodec, ProstCodec};

/// 100-message wire fixture. The message carries a `seq` field so any
/// reorder in the round-trip is observable as `received[i].seq != i`.
#[derive(Clone, PartialEq, prost::Message)]
struct StreamItem {
    #[prost(uint32, tag = "1")]
    seq: u32,
    #[prost(string, tag = "2")]
    label: String,
    /// Variable-size payload so the LPM framing has different lengths
    /// for adjacent messages — a length-tracking bug at the framer
    /// would surface as truncated / overlapping decodes that no
    /// fixed-size fixture would catch.
    #[prost(bytes = "vec", tag = "3")]
    payload: Vec<u8>,
}

const STREAM_LEN: u32 = 100;
type StreamCodec = FramedCodec<ProstCodec<StreamItem, StreamItem>>;

fn build_fixture_stream() -> Vec<StreamItem> {
    (0..STREAM_LEN)
        .map(|i| StreamItem {
            seq: i,
            label: format!("msg-{i:03}"),
            // Payload size cycles through a small set so adjacent
            // frames have different lengths but the total stays
            // bounded. (i % 7) * 11 gives 0/11/22/33/44/55/66 byte
            // payloads, repeated.
            payload: vec![(i & 0xFF) as u8; ((i % 7) * 11) as usize],
        })
        .collect()
}

fn encode_fixture_stream(send: &[StreamItem], encode_error: &str) -> BytesMut {
    let mut wire = BytesMut::with_capacity(8 * 1024);
    let mut encoder = StreamCodec::new(ProstCodec::new());
    for item in send {
        encoder.encode_message(item, &mut wire).expect(encode_error);
    }
    wire
}

fn decode_available(
    decoder: &mut StreamCodec,
    buf: &mut BytesMut,
    decode_error: &str,
) -> Vec<StreamItem> {
    let mut out = Vec::new();
    while let Some(item) = decoder.decode_message(buf).expect(decode_error) {
        out.push(item);
    }
    out
}

fn stream_fingerprint(stream: &[StreamItem]) -> String {
    let mut hash = 14_695_981_039_346_656_037_u64;
    let mut total_payload_bytes = 0usize;

    for item in stream {
        total_payload_bytes += item.payload.len();
        hash ^= u64::from(item.seq);
        hash = hash.wrapping_mul(1_099_511_628_211);
        hash ^= item.label.len() as u64;
        hash = hash.wrapping_mul(1_099_511_628_211);
        hash ^= item.payload.len() as u64;
        hash = hash.wrapping_mul(1_099_511_628_211);
    }

    let first = stream
        .first()
        .map_or_else(|| "none".to_string(), |item| item.seq.to_string());
    let last = stream
        .last()
        .map_or_else(|| "none".to_string(), |item| item.seq.to_string());
    format!(
        "count={},first={},last={},payload_bytes={},fnv1a64={hash:016x}",
        stream.len(),
        first,
        last,
        total_payload_bytes,
    )
}

#[test]
fn server_streaming_round_trip_preserves_order_for_100_messages() {
    let send: Vec<StreamItem> = build_fixture_stream();

    // Encode all messages back-to-back into a single buffer — the
    // way an HTTP/2 DATA-frame body would carry a server-streaming
    // response.
    let mut wire = encode_fixture_stream(
        &send,
        "encode_message must succeed for fixture-sized payload",
    );

    // Decode the buffer one message at a time. The decoder MUST
    // return the messages in the SAME order they were encoded.
    let mut received: Vec<StreamItem> = Vec::with_capacity(send.len());
    let mut decoder = StreamCodec::new(ProstCodec::new());
    while !wire.is_empty() {
        match decoder
            .decode_message(&mut wire)
            .expect("decode_message must not error on a self-encoded buffer")
        {
            Some(msg) => received.push(msg),
            None => panic!(
                "decode_message returned Ok(None) with {} bytes still buffered — \
                 framer should have produced exactly STREAM_LEN messages",
                wire.len(),
            ),
        }
    }

    assert_eq!(
        received.len(),
        send.len(),
        "decoded message count must match encoded count",
    );
    for (i, (sent, got)) in send.iter().zip(received.iter()).enumerate() {
        assert_eq!(got, sent, "message at index {i} drifted in round-trip");
        assert_eq!(
            got.seq, i as u32,
            "seq field must match position — receive order != send order at index {i}",
        );
    }
}

#[test]
fn server_streaming_partial_buffer_decodes_remaining_after_more_arrives() {
    // Pin the streaming-decoder invariant that splitting the wire
    // mid-frame (the way TCP segmentation would deliver bytes) does
    // NOT cause re-order or message loss. Encode 100 messages, decode
    // the first ~half, append the rest, decode the rest.
    let send = build_fixture_stream();
    let full_wire = encode_fixture_stream(&send, "encode");

    // Split the buffer somewhere mid-stream that's NOT on a frame
    // boundary — pick a byte offset that we know is in the middle of
    // a message body.
    let mid = full_wire.len() / 3;
    let mut partial = BytesMut::from(&full_wire[..mid]);
    let tail = full_wire[mid..].to_vec();

    let mut received: Vec<StreamItem> = Vec::with_capacity(send.len());
    let mut decoder = StreamCodec::new(ProstCodec::new());

    // Drain whatever frames are completable from the partial buffer.
    while let Some(msg) = decoder
        .decode_message(&mut partial)
        .expect("partial decode")
    {
        received.push(msg);
    }
    let half_count = received.len();
    assert!(
        half_count < send.len(),
        "partial buffer must NOT yield all messages — split chosen too \
         coarsely. mid={mid}, full_len={}",
        full_wire.len(),
    );

    // Append the tail and continue decoding. The decoder keeps its
    // partial-frame state; the rest of the messages must arrive in
    // sequence.
    partial.extend_from_slice(&tail);
    while !partial.is_empty() {
        match decoder.decode_message(&mut partial).expect("rest decode") {
            Some(msg) => received.push(msg),
            None => panic!(
                "Ok(None) with {} bytes still in buffer — decoder lost framing",
                partial.len(),
            ),
        }
    }

    assert_eq!(received.len(), send.len(), "must recover full sequence");
    for (i, (sent, got)) in send.iter().zip(received.iter()).enumerate() {
        assert_eq!(
            got, sent,
            "split round-trip drifted at index {i} (split-half boundary={half_count})",
        );
    }
}

#[test]
fn conformance_grpc_streaming_ordering_matrix_logs_fingerprints() {
    const EXACT_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_2gblyo_streaming cargo test -p asupersync --test grpc_streaming_ordering_conformance -- --nocapture";

    let log_case = |scenario_id: &str,
                    message_count: usize,
                    frame_count: usize,
                    split_pattern: &str,
                    input_order_fingerprint: &str,
                    output_order_fingerprint: &str,
                    cancellation_point: &str,
                    error_kind: &str| {
        eprintln!(
            "GRPC_STREAM_ORDERING scenario_id={} message_count={} frame_count={} split_pattern={} input_order_fingerprint={} output_order_fingerprint={} cancellation_point={} error_kind={} exact_rch_command=\"{}\" artifact_paths=none final_ordering_preservation_verdict=pass",
            scenario_id,
            message_count,
            frame_count,
            split_pattern,
            input_order_fingerprint,
            output_order_fingerprint,
            cancellation_point,
            error_kind,
            EXACT_RCH_COMMAND,
        );
    };

    let empty_send: Vec<StreamItem> = Vec::new();
    let mut empty_wire = encode_fixture_stream(&empty_send, "encode empty");
    let mut empty_decoder = StreamCodec::new(ProstCodec::new());
    let empty_received = decode_available(&mut empty_decoder, &mut empty_wire, "decode empty");
    assert!(
        empty_wire.is_empty(),
        "empty stream should leave no buffered bytes"
    );
    assert_eq!(empty_received, empty_send, "empty stream must round-trip");
    log_case(
        "empty_stream",
        0,
        0,
        "joined",
        &stream_fingerprint(&empty_send),
        &stream_fingerprint(&empty_received),
        "none",
        "ok",
    );

    let single_send = vec![build_fixture_stream()[0].clone()];
    let mut single_wire = encode_fixture_stream(&single_send, "encode single");
    let mut single_decoder = StreamCodec::new(ProstCodec::new());
    let single_received = decode_available(&mut single_decoder, &mut single_wire, "decode single");
    assert!(
        single_wire.is_empty(),
        "single-message stream must fully drain"
    );
    assert_eq!(
        single_received, single_send,
        "single-message stream must round-trip"
    );
    log_case(
        "single_message",
        1,
        1,
        "joined",
        &stream_fingerprint(&single_send),
        &stream_fingerprint(&single_received),
        "none",
        "ok",
    );

    let full_send = build_fixture_stream();
    let mut full_wire = encode_fixture_stream(&full_send, "encode full");
    let mut full_decoder = StreamCodec::new(ProstCodec::new());
    let full_received = decode_available(&mut full_decoder, &mut full_wire, "decode full");
    assert!(
        full_wire.is_empty(),
        "100-message joined stream must fully drain"
    );
    assert_eq!(
        full_received, full_send,
        "100-message joined stream must preserve order"
    );
    log_case(
        "hundred_messages_joined",
        full_send.len(),
        full_send.len(),
        "joined",
        &stream_fingerprint(&full_send),
        &stream_fingerprint(&full_received),
        "none",
        "ok",
    );

    let split_send = build_fixture_stream();
    let split_wire = encode_fixture_stream(&split_send, "encode split");
    let split_at = split_wire.len() / 3;
    let mut split_buf = BytesMut::from(&split_wire[..split_at]);
    let tail = split_wire[split_at..].to_vec();
    let mut split_decoder = StreamCodec::new(ProstCodec::new());
    let mut split_received =
        decode_available(&mut split_decoder, &mut split_buf, "decode split partial");
    let first_chunk_count = split_received.len();
    assert!(
        first_chunk_count < split_send.len(),
        "partial split must pause before the full stream is available"
    );
    split_buf.extend_from_slice(&tail);
    split_received.extend(decode_available(
        &mut split_decoder,
        &mut split_buf,
        "decode split tail",
    ));
    assert!(
        split_buf.is_empty(),
        "split stream must fully drain after tail arrives"
    );
    assert_eq!(
        split_received, split_send,
        "split stream must preserve full order"
    );
    log_case(
        "hundred_messages_fragmented",
        split_send.len(),
        split_send.len(),
        &format!("prefix={}bytes_then_tail", split_at),
        &stream_fingerprint(&split_send),
        &stream_fingerprint(&split_received),
        "none",
        "ok",
    );

    let cancel_like_send = build_fixture_stream();
    let cancel_like_wire = encode_fixture_stream(&cancel_like_send, "encode cancel-like");
    let cancel_split_at = cancel_like_wire.len() / 3;
    let mut cancel_buf = BytesMut::from(&cancel_like_wire[..cancel_split_at]);
    let cancel_tail = cancel_like_wire[cancel_split_at..].to_vec();
    let (mut cancel_like_received, cancellation_point) = {
        let mut first_decoder = StreamCodec::new(ProstCodec::new());
        let cancel_like_received = decode_available(
            &mut first_decoder,
            &mut cancel_buf,
            "decode cancel-like prefix",
        );
        let cancellation_point = cancel_like_received.len();
        assert!(
            cancellation_point < cancel_like_send.len(),
            "cancel-like split must stop mid-stream before full delivery"
        );
        (cancel_like_received, cancellation_point)
    };
    cancel_buf.extend_from_slice(&cancel_tail);
    let mut resumed_decoder = StreamCodec::new(ProstCodec::new());
    cancel_like_received.extend(decode_available(
        &mut resumed_decoder,
        &mut cancel_buf,
        "decode cancel-like resume",
    ));
    assert!(
        cancel_buf.is_empty(),
        "resume after cancel-like drop must fully drain remaining bytes"
    );
    assert_eq!(
        cancel_like_received, cancel_like_send,
        "resume after cancel-like drop must not duplicate or lose messages"
    );
    log_case(
        "hundred_messages_resume_after_cancellation_like_drop",
        cancel_like_send.len(),
        cancel_like_send.len(),
        &format!("prefix={}bytes_then_tail", cancel_split_at),
        &stream_fingerprint(&cancel_like_send),
        &stream_fingerprint(&cancel_like_received),
        &format!(
            "after_message_index={}",
            cancellation_point.saturating_sub(1)
        ),
        "ok",
    );
}
