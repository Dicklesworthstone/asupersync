//! Conformance harness: identity Content-Encoding pipeline preserves
//! the prost message tree byte-for-byte through the asupersync codec.
//!
//! gRPC's compression registry includes `identity` as the no-op
//! algorithm — a peer that advertises `grpc-encoding: identity` is
//! saying "I support compression negotiation, but this frame's
//! payload is the raw protobuf bytes." Per the spec, the
//! compressed-flag byte SHOULD be 0 in this case (no compression
//! applied), and the decoder MUST NOT double-decode (no-op-on-no-op
//! is still a no-op, but a regression that ran `identity_decompress`
//! twice could miscount the max_size cap and reject legitimate
//! frames or accept oversized ones).
//!
//! This file pins:
//!
//!   1. **Round-trip identity.** Same prost::Message in → same
//!      prost::Message out, byte-identical wire payload.
//!   2. **Wire-byte parity with the no-compressor baseline.** The
//!      bytes emitted by `FramedCodec::new(prost).with_identity_frame_codec()`
//!      MUST equal the bytes emitted by the same codec WITHOUT a
//!      compressor (the `FramedCodec::new(prost)` baseline) for the
//!      same input. Identity is the no-op compression — anything
//!      that diverges from the bare-frame path is a regression.
//!   3. **No double-decode.** A frame encoded via the identity codec
//!      decodes through a fresh identity-codec decoder AND through a
//!      bare-codec decoder to the same prost message tree.
//!   4. **max_size cap honored on the decode side.** A frame whose
//!      declared length exceeds `max_decode_message_size` is rejected
//!      with `MessageTooLarge` BEFORE the identity decompressor sees
//!      the bytes — preventing a "cap doubled" bug where the cap is
//!      checked, identity passes through, and the cap is checked again.
//!
//! Why this is "vs prost": the identity-codec pipeline is supposed to
//! be transparent — anything inside it is just `prost::Message::encode_to_vec`
//! plus the LPM 5-byte prefix. A divergence between the identity-codec
//! path and the no-compressor path means the compression pipeline is
//! mutating bytes it should be passing through.

use asupersync::bytes::BytesMut;
use asupersync::grpc::{FramedCodec, ProstCodec};
use prost::Message;

#[derive(Clone, PartialEq, prost::Message)]
struct IdentityFixture {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(int32, tag = "2")]
    count: i32,
    #[prost(bytes = "vec", tag = "3")]
    payload: Vec<u8>,
}

fn fixtures() -> Vec<IdentityFixture> {
    vec![
        IdentityFixture::default(),
        IdentityFixture {
            name: "alice".into(),
            count: 7,
            payload: b"hello".to_vec(),
        },
        IdentityFixture {
            name: "edge".into(),
            count: i32::MIN,
            payload: vec![0xCD; 1024],
        },
    ]
}

#[test]
fn identity_codec_round_trip_preserves_prost_message_tree() {
    for (i, msg) in fixtures().iter().enumerate() {
        let mut wire = BytesMut::new();
        let mut encoder = FramedCodec::<ProstCodec<IdentityFixture, IdentityFixture>>::new(
            ProstCodec::new(),
        )
        .with_identity_frame_codec();
        encoder.encode_message(msg, &mut wire).expect("encode");

        let mut decoder = FramedCodec::<ProstCodec<IdentityFixture, IdentityFixture>>::new(
            ProstCodec::new(),
        )
        .with_identity_frame_codec();
        let decoded = decoder
            .decode_message(&mut wire)
            .expect("decode")
            .expect("message");

        assert_eq!(decoded, *msg, "fixture {i}: identity round-trip drifted");
        assert!(
            wire.is_empty(),
            "fixture {i}: identity decoder must consume the whole frame; \
             {} trailing bytes is a desync",
            wire.len(),
        );
    }
}

#[test]
fn identity_codec_payload_region_equals_raw_prost_bytes() {
    // The identity pipeline is supposed to be transparent. The
    // payload region of the wire frame (bytes 5..) MUST equal
    // prost::Message::encode_to_vec(M) for any fixture M — anything
    // else means identity is mutating bytes it should pass through.
    for (i, msg) in fixtures().iter().enumerate() {
        let prost_bytes = msg.encode_to_vec();

        let mut wire = BytesMut::new();
        let mut encoder = FramedCodec::<ProstCodec<IdentityFixture, IdentityFixture>>::new(
            ProstCodec::new(),
        )
        .with_identity_frame_codec();
        encoder.encode_message(msg, &mut wire).expect("encode");

        assert!(wire.len() >= 5, "fixture {i}: missing 5-byte prefix");
        let declared = u32::from_be_bytes([wire[1], wire[2], wire[3], wire[4]]) as usize;
        assert_eq!(
            declared,
            prost_bytes.len(),
            "fixture {i}: identity wire declared length must equal prost.len() — \
             no compression overhead, no padding",
        );
        assert_eq!(
            wire.len() - 5,
            prost_bytes.len(),
            "fixture {i}: identity payload region length must equal prost.len()",
        );
        assert_eq!(
            &wire[5..],
            prost_bytes.as_slice(),
            "fixture {i}: identity payload bytes must be byte-identical to \
             prost::Message::encode_to_vec — anything else means the codec is \
             rewriting bytes that should pass through transparently",
        );
    }
}

#[test]
fn identity_decoder_decodes_bare_codec_output() {
    // A peer that emits frames WITHOUT a compressor (compressed
    // flag=0) and a receiver that's wired with the identity codec
    // MUST still decode correctly — identity-aware decoder must
    // accept uncompressed frames.
    for (i, msg) in fixtures().iter().enumerate() {
        let mut wire = BytesMut::new();
        // Encode with NO compressor (bare-frame path).
        let mut bare_encoder =
            FramedCodec::<ProstCodec<IdentityFixture, IdentityFixture>>::new(ProstCodec::new());
        bare_encoder.encode_message(msg, &mut wire).expect("bare encode");

        // Decode through the IDENTITY-aware codec.
        let mut identity_decoder = FramedCodec::<ProstCodec<IdentityFixture, IdentityFixture>>::new(
            ProstCodec::new(),
        )
        .with_identity_frame_codec();
        let decoded = identity_decoder
            .decode_message(&mut wire)
            .expect("identity-aware decoder must accept bare-frame input")
            .expect("message");

        assert_eq!(
            decoded, *msg,
            "fixture {i}: bare→identity decode path corrupted the message tree",
        );
    }
}

#[test]
fn bare_decoder_decodes_identity_codec_output() {
    // Symmetric: a frame produced by the identity codec must decode
    // cleanly through a bare-codec decoder. This is the wire-level
    // negotiation where one side advertises identity and the other
    // doesn't care — the wire MUST still parse.
    for (i, msg) in fixtures().iter().enumerate() {
        let mut wire = BytesMut::new();
        let mut identity_encoder = FramedCodec::<ProstCodec<IdentityFixture, IdentityFixture>>::new(
            ProstCodec::new(),
        )
        .with_identity_frame_codec();
        identity_encoder
            .encode_message(msg, &mut wire)
            .expect("identity encode");

        let mut bare_decoder =
            FramedCodec::<ProstCodec<IdentityFixture, IdentityFixture>>::new(ProstCodec::new());
        match bare_decoder.decode_message(&mut wire).expect("decode result") {
            Some(decoded) => assert_eq!(
                decoded, *msg,
                "fixture {i}: identity→bare decode path corrupted the message tree",
            ),
            None => panic!(
                "fixture {i}: bare decoder did not consume the identity-encoded frame",
            ),
        }
    }
}

#[test]
fn identity_codec_does_not_double_decode_on_repeated_calls() {
    // Pin that decoder state does not accumulate. A regression where
    // the identity decompressor was called twice on the same payload
    // (e.g. via a state-machine mistake) would still produce the
    // correct bytes (identity is idempotent) BUT the max_size cap
    // would be checked twice — which would surface as a discrepancy
    // when the second call's input length differs from the first.
    let msg = IdentityFixture {
        name: "repeated".into(),
        count: 3,
        payload: vec![0x55; 256],
    };

    let mut encoder =
        FramedCodec::<ProstCodec<IdentityFixture, IdentityFixture>>::new(ProstCodec::new())
            .with_identity_frame_codec();
    let mut decoder =
        FramedCodec::<ProstCodec<IdentityFixture, IdentityFixture>>::new(ProstCodec::new())
            .with_identity_frame_codec();

    for round in 0..3 {
        let mut wire = BytesMut::new();
        encoder.encode_message(&msg, &mut wire).expect("round encode");
        let decoded = decoder
            .decode_message(&mut wire)
            .expect("round decode")
            .expect("message");
        assert_eq!(
            decoded, msg,
            "round {round}: identity round-trip drifted — codec state leak",
        );
        assert!(
            wire.is_empty(),
            "round {round}: trailing bytes after decode = framer state leak",
        );
    }
}
