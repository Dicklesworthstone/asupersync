//! Audit + regression test for `src/grpc/server.rs` aggregate
//! request-body cap end-to-end behavior (tick #205, follow-up
//! to ticks #203 + #204).
//!
//! Operator's question: "verify request body upload aggregate
//! cap." Audit-of-the-fix from #204. Tick #204's 12 tests
//! cover the API surface; this test pins the END-TO-END
//! transport-adapter usage pattern AND the integration with
//! existing per-message + per-stream-buffer caps.
//!
//! Audit findings:
//!
//!   (a) **Layered cap interaction**: a single call subject to
//!       BOTH per-message cap (max_recv_message_size) AND
//!       aggregate cap (max_request_body_bytes) is rejected
//!       by whichever fires FIRST. The server-created codec now owns the
//!       aggregate meter and charges real decoded LPM payloads.
//!
//!   (b) **Aggregate cap + None per-message cap**: when the
//!       per-message cap is generous (4 MiB) but aggregate
//!       cap is tight (256 KiB), the aggregate cap fires
//!       FIRST — the very first 256 KiB+1 message rejects.
//!
//!   (c) **Production codec integration**: `Server::framed_codec` binds one
//!       meter to each call. Reusing that codec for client streaming counts
//!       every decoded message and fails closed before over-cap delivery.
//!
//!   (d) **Cap independent of per-message cap**: a server
//!       configured with per-message 4 MiB and aggregate
//!       512 KiB rejects on the FIRST decoded message that
//!       exceeds 512 KiB — even though the per-message cap
//!       would have allowed 4 MiB.
//!
//!   (e) **State persists across record calls**: the meter's
//!       `bytes_accumulated()` accurately reflects the
//!       cumulative total — regression that reset on each
//!       call would break the aggregate semantics.
//!
//! Regression tests below pin (a)-(e) at the public API
//! surface.

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::grpc::server::RequestBodyMeter;
use asupersync::grpc::status::Code;
use asupersync::grpc::{FramedCodec, GrpcError, IdentityCodec, ServerBuilder, ServerConfig};

fn encode_identity_frames(payloads: &[Bytes]) -> BytesMut {
    let mut encoder = FramedCodec::new(IdentityCodec);
    let mut wire = BytesMut::new();
    for payload in payloads {
        encoder
            .encode_message(payload, &mut wire)
            .expect("identity request frame must encode");
    }
    wire
}

#[test]
fn server_codec_enforces_client_streaming_aggregate_at_decode_boundary() {
    let server = ServerBuilder::new()
        .max_recv_message_size(16)
        .max_request_body_bytes(7)
        .build();
    let mut decoder = server.framed_codec(IdentityCodec);
    let mut wire = encode_identity_frames(&[
        Bytes::from_static(b"abc"),
        Bytes::from_static(b"defg"),
        Bytes::from_static(b"h"),
    ]);

    assert_eq!(
        decoder.decode_message(&mut wire).expect("first decode"),
        Some(Bytes::from_static(b"abc"))
    );
    assert_eq!(
        decoder.decode_message(&mut wire).expect("at-cap decode"),
        Some(Bytes::from_static(b"defg"))
    );
    assert_eq!(decoder.request_body_meter().bytes_accumulated(), 7);

    let error = decoder
        .decode_message(&mut wire)
        .expect_err("cap-plus-one message must reject before delivery");
    let GrpcError::Status(status) = error else {
        panic!("aggregate body rejection must preserve its typed status")
    };
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert!(status.message().contains("8 bytes > 7 bytes"));
    assert_eq!(decoder.request_body_meter().bytes_accumulated(), 8);
    assert!(decoder.is_poisoned(), "over-cap stream must fail closed");
    assert!(wire.is_empty(), "buffered later frames must be discarded");
}

#[test]
fn server_codecs_keep_aggregate_state_per_call() {
    let server = ServerBuilder::new().max_request_body_bytes(4).build();
    let payload = Bytes::from_static(b"four");
    let mut first = server.framed_codec(IdentityCodec);
    let mut second = server.framed_codec(IdentityCodec);

    for decoder in [&mut first, &mut second] {
        let mut wire = encode_identity_frames(std::slice::from_ref(&payload));
        assert_eq!(
            decoder.decode_message(&mut wire).expect("per-call decode"),
            Some(payload.clone())
        );
        assert_eq!(decoder.request_body_meter().bytes_accumulated(), 4);
    }
}

#[test]
fn partial_frame_polls_charge_one_successful_decode_exactly_once() {
    let server = ServerBuilder::new().max_request_body_bytes(3).build();
    let mut decoder = server.framed_codec(IdentityCodec);
    let mut complete = encode_identity_frames(&[Bytes::from_static(b"abc")]);
    let mut partial = complete.split_to(4);

    assert_eq!(
        decoder
            .decode_message(&mut partial)
            .expect("partial prefix is not an error"),
        None
    );
    assert_eq!(decoder.request_body_meter().bytes_accumulated(), 0);

    partial.extend_from_slice(&complete);
    assert_eq!(
        decoder
            .decode_message(&mut partial)
            .expect("completed frame"),
        Some(Bytes::from_static(b"abc"))
    );
    assert_eq!(decoder.request_body_meter().bytes_accumulated(), 3);
    assert_eq!(
        decoder.decode_message(&mut partial).expect("empty buffer"),
        None
    );
    assert_eq!(decoder.request_body_meter().bytes_accumulated(), 3);
}

fn collapse_frame(_input: Bytes) -> Result<Bytes, GrpcError> {
    Ok(Bytes::from_static(b"x"))
}

fn expand_frame(_input: Bytes, _max_size: usize) -> Result<Bytes, GrpcError> {
    Ok(Bytes::from_static(b"decoded"))
}

#[test]
fn aggregate_limit_counts_decompressed_payload_not_wire_size() {
    let server = ServerBuilder::new().max_request_body_bytes(6).build();
    let mut encoder =
        FramedCodec::new(IdentityCodec).with_frame_codec(collapse_frame, expand_frame);
    let mut wire = BytesMut::new();
    encoder
        .encode_message(&Bytes::from_static(b"ignored"), &mut wire)
        .expect("compressed request frame must encode");
    assert_eq!(wire.len(), 6, "wire is five-byte prefix plus one byte");

    let mut decoder = server
        .framed_codec(IdentityCodec)
        .with_frame_codec(collapse_frame, expand_frame);
    let error = decoder
        .decode_message(&mut wire)
        .expect_err("seven decompressed bytes must exceed the six-byte cap");
    let GrpcError::Status(status) = error else {
        panic!("decoded-body rejection must preserve ResourceExhausted")
    };
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert!(status.message().contains("7 bytes > 6 bytes"));
    assert_eq!(decoder.request_body_meter().bytes_accumulated(), 7);
}

#[test]
fn aggregate_cap_fires_after_n_under_cap_messages() {
    // Pin (a): a stream of 256 KiB messages each under the
    // per-message cap, but aggregate cap is 1 MiB. The 5th
    // message (which would push total to 1.25 MiB) rejects.
    let server = ServerBuilder::new()
        .max_recv_message_size(512 * 1024) // per-message OK
        .max_request_body_bytes(1024 * 1024) // aggregate 1 MiB
        .build();
    let mut meter = RequestBodyMeter::from_config(server.config());

    // Four 256 KiB messages = 1024 KiB exactly = 1 MiB.
    for i in 0..4 {
        meter
            .record_message_bytes(256 * 1024)
            .unwrap_or_else(|e| panic!("message {i}: {e:?}"));
    }
    assert_eq!(meter.bytes_accumulated(), 1024 * 1024);

    // 5th message would push total to 1.25 MiB — over cap.
    let err = meter
        .record_message_bytes(256 * 1024)
        .expect_err("5th message exceeds 1 MiB aggregate cap");
    assert_eq!(err.code(), Code::ResourceExhausted);
}

#[test]
fn aggregate_cap_fires_on_first_oversize_message() {
    // Pin (b)+(d): aggregate cap is INDEPENDENT of per-message
    // cap. A single 600 KiB message rejects against a 512 KiB
    // aggregate cap, even though per-message cap is 4 MiB.
    let server = ServerBuilder::new()
        .max_recv_message_size(4 * 1024 * 1024) // 4 MiB per-message
        .max_request_body_bytes(512 * 1024) // 512 KiB aggregate
        .build();
    let mut meter = RequestBodyMeter::from_config(server.config());

    let err = meter
        .record_message_bytes(600 * 1024)
        .expect_err("600 KiB > 512 KiB aggregate cap");
    assert_eq!(err.code(), Code::ResourceExhausted);
}

#[test]
fn adapter_integration_pattern_simulated() {
    // Pin (c): documented adapter usage. Simulate the
    // transport adapter loop: receive Bytes, decode message
    // body length, call record_message_bytes, push to
    // StreamingRequest.
    let server = ServerBuilder::new()
        .max_request_body_bytes(2 * 1024 * 1024) // 2 MiB aggregate
        .build();
    let mut meter = RequestBodyMeter::from_config(server.config());

    // Simulated decode loop: 8 messages of 200 KiB = 1.6 MiB.
    let messages: Vec<usize> = vec![200 * 1024; 8];
    let mut delivered: Vec<usize> = Vec::new();
    for size in messages {
        match meter.record_message_bytes(size) {
            Ok(()) => delivered.push(size),
            Err(_) => break,
        }
    }
    assert_eq!(
        delivered.len(),
        8,
        "all 8 messages of 200 KiB fit under 2 MiB aggregate cap",
    );
    assert_eq!(meter.bytes_accumulated(), 8 * 200 * 1024);
}

#[test]
fn adapter_pattern_rejects_at_correct_message() {
    // Pin (c) extension: the adapter's loop terminates at
    // the EXACT message that exceeds the cap. Pin the
    // boundary precisely.
    let server = ServerBuilder::new()
        .max_request_body_bytes(1024 * 1024) // 1 MiB
        .build();
    let mut meter = RequestBodyMeter::from_config(server.config());

    let messages: Vec<usize> = vec![300 * 1024; 10]; // 10 × 300 KiB = 3 MiB
    let mut accepted = 0;
    let mut rejection_at: Option<usize> = None;
    for (idx, size) in messages.into_iter().enumerate() {
        match meter.record_message_bytes(size) {
            Ok(()) => accepted += 1,
            Err(_) => {
                rejection_at = Some(idx);
                break;
            }
        }
    }
    // 3 messages × 300 KiB = 900 KiB (under 1 MiB)
    // 4th message (1.2 MiB total) exceeds the 1 MiB cap.
    assert_eq!(
        accepted, 3,
        "first 3 messages (900 KiB total) accept; 4th rejects",
    );
    assert_eq!(
        rejection_at,
        Some(3),
        "rejection fires at the 4th (zero-indexed: 3) message",
    );
}

#[test]
fn cumulative_state_persists_across_record_calls() {
    // Pin (e): bytes_accumulated reflects cumulative total —
    // a regression that reset on each call would silently
    // never reject.
    let mut meter = RequestBodyMeter::new(Some(10 * 1024));
    assert_eq!(meter.bytes_accumulated(), 0);
    meter.record_message_bytes(1024).expect("1 KiB");
    assert_eq!(meter.bytes_accumulated(), 1024);
    meter.record_message_bytes(2048).expect("2 KiB more");
    assert_eq!(meter.bytes_accumulated(), 3 * 1024);
    meter.record_message_bytes(4096).expect("4 KiB more");
    assert_eq!(meter.bytes_accumulated(), 7 * 1024);
}

#[test]
fn aggregate_cap_disabled_under_default_config() {
    // Pin: a server using all defaults has NO aggregate cap
    // (None). The fix is opt-in; existing deployments
    // continue to work.
    let server = ServerBuilder::new().build();
    let mut meter = RequestBodyMeter::from_config(server.config());
    assert!(meter.cap().is_none());
    // 4 GiB total accepts (no cap to enforce).
    for _ in 0..1024 {
        meter
            .record_message_bytes(4 * 1024 * 1024)
            .expect("None cap");
    }
    assert_eq!(meter.bytes_accumulated(), 1024 * 4 * 1024 * 1024);
}

#[test]
fn aggregate_cap_zero_blocks_any_message() {
    // Pin edge: a configured cap of 0 rejects EVERY non-zero
    // message. (Operators that want "no upload allowed"
    // should use this rather than relying on `None` which
    // means UNLIMITED.)
    let server = ServerBuilder::new().max_request_body_bytes(0).build();
    let mut meter = RequestBodyMeter::from_config(server.config());
    let err = meter
        .record_message_bytes(1)
        .expect_err("0 cap rejects 1 byte");
    assert_eq!(err.code(), Code::ResourceExhausted);
    // 0-byte message is OK (0 > 0 is false; strict > boundary).
    let mut fresh = RequestBodyMeter::new(Some(0));
    fresh
        .record_message_bytes(0)
        .expect("0 bytes is OK at 0 cap");
}

#[test]
fn meter_rejection_short_circuits_remaining_decode_loop() {
    // Pin (c): once the meter rejects, the adapter MUST stop
    // decoding the rest of the stream. This is the documented
    // contract — the rejection surfaces to the call.
    let mut meter = RequestBodyMeter::new(Some(1024));
    meter.record_message_bytes(800).expect("under cap");
    let err = meter
        .record_message_bytes(300)
        .expect_err("over cap rejects");
    assert_eq!(err.code(), Code::ResourceExhausted);

    // Subsequent calls also reject — the meter's accumulator
    // has already crossed the cap, every additional record
    // continues to exceed it.
    let err2 = meter
        .record_message_bytes(1)
        .expect_err("post-rejection state continues to reject");
    assert_eq!(err2.code(), Code::ResourceExhausted);
}

#[test]
fn aggregate_cap_does_not_silently_loosen_per_message_cap() {
    // Pin (a) interaction inverse: a server with TIGHT
    // per-message (256 KiB) and LOOSE aggregate (16 MiB)
    // does NOT let a single 1 MiB message through (because
    // the per-message cap fires at the codec layer, audited
    // tick #163, not at the aggregate-meter layer).
    //
    // We can't directly test this here (per-message cap is
    // enforced at the FramedCodec layer, not at the meter),
    // but we pin the meter's behavior: a 1 MiB record is
    // ACCEPTED by the meter (because 1 MiB < 16 MiB
    // aggregate cap). The per-message rejection happens
    // upstream of the meter.
    let server = ServerBuilder::new()
        .max_recv_message_size(256 * 1024) // per-message tight
        .max_request_body_bytes(16 * 1024 * 1024) // aggregate loose
        .build();
    let mut meter = RequestBodyMeter::from_config(server.config());
    // Meter alone accepts 1 MiB (under 16 MiB aggregate).
    // The per-message rejection is enforced upstream by the
    // codec — NOT by the meter.
    meter
        .record_message_bytes(1024 * 1024)
        .expect("under aggregate cap");
}

#[test]
fn server_builder_chains_with_other_caps_without_collision() {
    // Pin: max_request_body_bytes builder method composes with
    // max_recv_message_size + max_metadata_size + others. A
    // regression that overwrote a sibling field would surface.
    let server = ServerBuilder::new()
        .max_recv_message_size(2 * 1024 * 1024)
        .max_send_message_size(4 * 1024 * 1024)
        .max_request_body_bytes(8 * 1024 * 1024)
        .max_metadata_size(16 * 1024)
        .build();
    let cfg = server.config();
    assert_eq!(cfg.max_recv_message_size, 2 * 1024 * 1024);
    assert_eq!(cfg.max_send_message_size, 4 * 1024 * 1024);
    assert_eq!(cfg.max_request_body_bytes, Some(8 * 1024 * 1024));
    assert_eq!(cfg.max_metadata_size, 16 * 1024);
}

#[test]
fn server_config_default_aggregate_cap_independent_of_per_message_default() {
    // Pin: changing the per-message cap default does NOT
    // implicitly change the aggregate cap default. They are
    // independent fields.
    let config = ServerConfig::default();
    assert_eq!(config.max_recv_message_size, 4 * 1024 * 1024);
    assert!(config.max_request_body_bytes.is_none());
}
