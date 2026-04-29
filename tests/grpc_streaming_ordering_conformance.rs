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

#[test]
fn server_streaming_round_trip_preserves_order_for_100_messages() {
    let send: Vec<StreamItem> = build_fixture_stream();

    // Encode all messages back-to-back into a single buffer — the
    // way an HTTP/2 DATA-frame body would carry a server-streaming
    // response.
    let mut wire = BytesMut::with_capacity(8 * 1024);
    let mut encoder = FramedCodec::<ProstCodec<StreamItem, StreamItem>>::new(ProstCodec::new());
    for item in &send {
        encoder
            .encode_message(item, &mut wire)
            .expect("encode_message must succeed for fixture-sized payload");
    }

    // Decode the buffer one message at a time. The decoder MUST
    // return the messages in the SAME order they were encoded.
    let mut received: Vec<StreamItem> = Vec::with_capacity(send.len());
    let mut decoder = FramedCodec::<ProstCodec<StreamItem, StreamItem>>::new(ProstCodec::new());
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
    let mut full_wire = BytesMut::with_capacity(8 * 1024);
    {
        let mut encoder =
            FramedCodec::<ProstCodec<StreamItem, StreamItem>>::new(ProstCodec::new());
        for item in &send {
            encoder
                .encode_message(item, &mut full_wire)
                .expect("encode");
        }
    }

    // Split the buffer somewhere mid-stream that's NOT on a frame
    // boundary — pick a byte offset that we know is in the middle of
    // a message body.
    let mid = full_wire.len() / 3;
    let mut partial = BytesMut::from(&full_wire[..mid]);
    let tail = full_wire[mid..].to_vec();

    let mut received: Vec<StreamItem> = Vec::with_capacity(send.len());
    let mut decoder = FramedCodec::<ProstCodec<StreamItem, StreamItem>>::new(ProstCodec::new());

    // Drain whatever frames are completable from the partial buffer.
    loop {
        match decoder.decode_message(&mut partial).expect("partial decode") {
            Some(msg) => received.push(msg),
            None => break,
        }
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
