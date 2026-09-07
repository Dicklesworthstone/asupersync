//! Crash/invariant fuzzer for native QUIC frames and the ATP stream codec.
//!
//! The target feeds adversarial packet payload bytes into `QuicFrame::decode`,
//! the parser used by the native QUIC receive path. Accepted frames must consume
//! input, produce non-empty diagnostics on typed errors, and re-encode into a
//! frame that the same parser can read again.
//!
//! ATP checks compare bulk and fragmented decoding of the same raw stream.
//! Every input also constructs a valid v0 frame, exercising canonical extension
//! order, all 22 frame families, truncated EOF, exact size bounds, duplicate and
//! reordered frame transcripts, and replay from a cloned transcript checkpoint.
//! This is codec coverage, not authenticated QUIC or session-resumption proof.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU32, Ordering};

use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, Encoder};
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::{Frame, FrameError, FrameType, ProtocolVersion};
use asupersync::net::atp::protocol::quic_frames::{QuicFrame, QuicFrameError};
use asupersync::net::atp::protocol::transcript::SessionTranscript;
use libfuzzer_sys::fuzz_target;

const MAX_PACKET_BYTES: usize = 4096;
const MAX_FRAMES_PER_PACKET: usize = 256;
const MAX_REENCODE_BYTES: usize = 8192;
// Diagnostic coverage only; oracle decisions never depend on this mask.
static OBSERVED_ATP_FAMILIES: AtomicU32 = AtomicU32::new(0);

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PACKET_BYTES {
        return;
    }

    let result = catch_unwind(AssertUnwindSafe(|| parse_packet_frames(data)));
    assert!(
        result.is_ok(),
        "QuicFrame::decode panicked while parsing {} packet bytes",
        data.len()
    );

    let chunk_size = usize::from(data.first().copied().unwrap_or(0) % 32) + 1;
    let bulk = decode_atp_stream(data, data.len().max(1));
    let fragmented = decode_atp_stream(data, chunk_size);
    assert!(
        bulk == fragmented,
        "ATP segmentation changed frames or error class: bytes={}, chunk_size={chunk_size}",
        data.len()
    );
    check_generated_atp_frame(data, chunk_size);
});

fn atp_error_class(error: &FrameError) -> &'static str {
    match error {
        FrameError::VarInt(_) => "varint",
        FrameError::UnknownFrameType(_) => "unknown_frame_type",
        FrameError::UnsupportedVersion(_) => "unsupported_version",
        FrameError::FrameTooLarge { .. } => "frame_too_large",
        FrameError::InvalidFormat(_) => "invalid_format",
        FrameError::UnexpectedEof => "unexpected_eof",
        FrameError::ExtensionTooLarge { .. } => "extension_too_large",
    }
}

fn decode_atp_stream(data: &[u8], chunk_size: usize) -> (Vec<Frame>, Option<&'static str>) {
    let mut codec = AtpFrameCodec::with_max_frame_size(MAX_REENCODE_BYTES as u64);
    let mut buffered = BytesMut::new();
    let mut frames = Vec::new();
    for chunk in data.chunks(chunk_size) {
        buffered.extend_from_slice(chunk);
        loop {
            let before = buffered.len();
            match codec.decode(&mut buffered) {
                Ok(Some(frame)) => {
                    assert!(buffered.len() < before, "ATP decoder made no progress");
                    frames.push(frame);
                }
                Ok(None) => break,
                Err(error) => return (frames, Some(atp_error_class(&error))),
            }
        }
    }
    match codec.decode_eof(&mut buffered) {
        Ok(None) => (frames, None),
        Ok(Some(_)) => panic!("ATP EOF produced a frame after decode reported incomplete"),
        Err(error) => (frames, Some(atp_error_class(&error))),
    }
}

fn check_generated_atp_frame(data: &[u8], chunk_size: usize) {
    const FAMILIES: [FrameType; 22] = [
        FrameType::Handshake,
        FrameType::HandshakeAck,
        FrameType::Capabilities,
        FrameType::CapabilitiesAck,
        FrameType::ObjectManifest,
        FrameType::ObjectRequest,
        FrameType::ObjectData,
        FrameType::ObjectComplete,
        FrameType::ObjectError,
        FrameType::PathUpdate,
        FrameType::PathChallenge,
        FrameType::PathResponse,
        FrameType::KeepAlive,
        FrameType::Cancel,
        FrameType::Error,
        FrameType::Close,
        FrameType::Control,
        FrameType::Data,
        FrameType::Proof,
        FrameType::Repair,
        FrameType::Session,
        FrameType::Manifest,
    ];
    let first = data.first().copied().unwrap_or(0);
    let second = data.get(1).copied().unwrap_or(0);
    let family_index = usize::from(first) % FAMILIES.len();
    let family = FAMILIES[family_index];
    let extension_id = u16::from_le_bytes([first, second]);
    let other_id = extension_id ^ u16::MAX;
    let extension = data[..data.len().min(8)].to_vec();
    let mut frame = Frame::new(ProtocolVersion::V0, family, data.to_vec())
        .expect("bounded generated ATP frame must be valid");
    frame
        .header
        .extensions
        .insert(extension_id, extension.clone());
    frame.header.extensions.insert(other_id, Vec::new());
    let wire = frame.to_wire_bytes().expect("generated ATP frame encodes");

    let mut reversed = frame.clone();
    reversed.header.extensions.clear();
    reversed.header.extensions.insert(other_id, Vec::new());
    reversed.header.extensions.insert(extension_id, extension);
    assert_eq!(
        wire,
        reversed
            .to_wire_bytes()
            .expect("reordered extensions encode"),
        "ATP canonical bytes depend on extension insertion order: {family:?}"
    );

    let split = usize::from(u16::from_le_bytes([second, first])) % wire.len();
    let mut codec = AtpFrameCodec::new();
    let mut prefix = BytesMut::from(&wire[..split]);
    assert!(codec.decode(&mut prefix).expect("valid prefix").is_none());
    let mut eof_codec = codec.clone();
    let eof = eof_codec.decode_eof(&mut prefix.clone());
    if split == 0 {
        assert!(matches!(eof, Ok(None)), "empty ATP EOF: {family:?}");
    } else {
        assert!(
            matches!(eof, Err(FrameError::UnexpectedEof)),
            "ATP truncated EOF: family={family:?}, split={split}"
        );
    }
    prefix.extend_from_slice(&wire[split..]);
    let decoded = codec.decode(&mut prefix).expect("resumed valid ATP frame");
    assert!(
        decoded.as_ref() == Some(&frame),
        "ATP resume changed {family:?}"
    );
    assert!(prefix.is_empty());
    assert!(
        codec
            .decode_eof(&mut prefix)
            .expect("clean ATP EOF")
            .is_none()
    );

    let mut limited = AtpFrameCodec::with_max_frame_size((wire.len() - 1) as u64);
    assert!(matches!(
        limited.decode(&mut BytesMut::from(wire.as_slice())),
        Err(FrameError::FrameTooLarge { .. })
    ));
    let mut destination = BytesMut::from(&[0x55][..]);
    assert!(matches!(
        limited.encode(frame.clone(), &mut destination),
        Err(FrameError::FrameTooLarge { .. })
    ));
    assert_eq!(
        destination.as_ref(),
        &[0x55],
        "ATP rejected encode wrote bytes"
    );

    let close = Frame::new(ProtocolVersion::V0, FrameType::Close, Vec::new())
        .expect("empty close frame is valid");
    let mut stream = wire.clone();
    stream.extend_from_slice(&close.to_wire_bytes().expect("close frame encodes"));
    stream.extend_from_slice(&wire);
    let (frames, error) = decode_atp_stream(&stream, chunk_size);
    assert!(error.is_none(), "ATP generated stream refused: {error:?}");
    assert!(
        frames == [frame.clone(), close.clone(), frame.clone()],
        "ATP framing lost order, duplicate, extension, or payload: {family:?}"
    );

    let mut checkpoint = SessionTranscript::new();
    checkpoint.add_frame(&frame);
    let single = checkpoint.current_hash();
    let mut replay = checkpoint.clone();
    replay.add_frame(&close);
    replay.add_frame(&frame);
    let mut decoded_transcript = SessionTranscript::new();
    for decoded in &frames {
        decoded_transcript.add_frame(decoded);
    }
    assert_eq!(replay.current_hash(), decoded_transcript.current_hash());
    assert_ne!(
        single,
        replay.current_hash(),
        "ATP transcript lost appended frames"
    );
    checkpoint.add_frame(&frame);
    checkpoint.add_frame(&close);
    assert_ne!(
        replay.current_hash(),
        checkpoint.current_hash(),
        "ATP transcript lost frame order: family={family:?}, schema=0"
    );
    let family_bit = 1 << family_index;
    if OBSERVED_ATP_FAMILIES.fetch_or(family_bit, Ordering::Relaxed) & family_bit == 0 {
        eprintln!(
            "ATP_FUZZ_FAMILY schema=0 family={family:?} transcript={single} input_bytes={} payload=redacted replay=libfuzzer-corpus",
            data.len()
        );
    }
}

fn parse_packet_frames(data: &[u8]) {
    let mut buf = data;
    let mut frames = 0usize;

    while !buf.is_empty() && frames < MAX_FRAMES_PER_PACKET {
        let before = buf.len();
        match QuicFrame::decode(&mut buf) {
            Ok(Some(frame)) => {
                frames += 1;
                assert!(
                    buf.len() < before,
                    "QuicFrame::decode accepted a frame without consuming bytes"
                );
                assert_accepted_frame_reencodes(&frame);
            }
            Ok(None) => {
                assert_eq!(
                    buf.len(),
                    before,
                    "QuicFrame::decode returned None after consuming bytes"
                );
                break;
            }
            Err(error) => {
                assert_typed_quic_error(&error);
                break;
            }
        }
    }
}

fn assert_accepted_frame_reencodes(frame: &QuicFrame) {
    let mut encoded = BytesMut::new();
    match frame.encode(&mut encoded) {
        Ok(()) => {}
        Err(error) => panic!("accepted QUIC frame failed to re-encode: {error:?}"),
    }

    assert!(
        encoded.len() <= MAX_REENCODE_BYTES,
        "accepted QUIC frame re-encoded to an unexpectedly large payload: {} bytes",
        encoded.len()
    );

    let mut encoded_slice = encoded.as_ref();
    let before = encoded_slice.len();
    match QuicFrame::decode(&mut encoded_slice) {
        Ok(Some(_)) => assert!(
            encoded_slice.len() < before,
            "re-encoded QUIC frame did not consume bytes on decode"
        ),
        Ok(None) => panic!("re-encoded QUIC frame decoded as incomplete"),
        Err(error) => panic!("re-encoded accepted QUIC frame failed to decode: {error:?}"),
    }
}

fn assert_typed_quic_error(error: &QuicFrameError) {
    let diagnostic = error.to_string();
    assert!(
        !diagnostic.trim().is_empty(),
        "QUIC frame parser error diagnostics must be non-empty"
    );

    match error {
        QuicFrameError::VarInt(_)
        | QuicFrameError::UnknownFrameType(_)
        | QuicFrameError::InvalidFormat(_)
        | QuicFrameError::UnexpectedEof
        | QuicFrameError::PayloadTooLarge { .. } => {}
    }
}
