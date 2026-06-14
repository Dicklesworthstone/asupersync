//! Contract tests for the crash-durable RaptorQ trace-journal frame format
//! (br-asupersync-raptorq-leverage-3bb2pl.2).
//!
//! Kept as a focused integration test (not inline lib unit tests) so it links
//! only the asupersync lib and not the conformance dev-dependency, giving a
//! reliable remote proof lane for this slice.

#![allow(missing_docs)]

use asupersync::trace::raptorq_journal::{
    JOURNAL_FLAG_CHECKPOINT_BOUNDARY, JOURNAL_FRAME_HEADER_LEN, JOURNAL_FRAME_MAGIC,
    JOURNAL_FRAME_VERSION, JournalFrame, JournalFrameError, crc32, scan_frames,
};

fn sample_frame() -> JournalFrame {
    JournalFrame::new(
        7,
        2,
        5,
        10,
        64,
        JOURNAL_FLAG_CHECKPOINT_BOUNDARY,
        b"checkpoint-symbol-payload".to_vec(),
    )
}

#[test]
fn crc32_matches_canonical_check_vector() {
    // The standard CRC-32/ISO-HDLC check value for the ASCII string "123456789".
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
}

#[test]
fn frame_roundtrips() {
    let frame = sample_frame();
    let encoded = frame.encode();
    assert_eq!(encoded.len(), frame.encoded_len());
    let (decoded, consumed) = JournalFrame::decode(&encoded).expect("decode");
    assert_eq!(consumed, encoded.len());
    assert_eq!(decoded, frame);
    assert!(decoded.header.is_checkpoint_boundary());
    assert_eq!(decoded.header.payload_len as usize, frame.payload.len());
}

#[test]
fn scan_recovers_multiple_frames_and_stops_at_a_torn_tail() {
    let mut buf = Vec::new();
    sample_frame().encode_into(&mut buf);
    sample_frame().encode_into(&mut buf);
    let intact = buf.len();
    // Simulate a torn final write: a partial third header.
    buf.extend_from_slice(&JOURNAL_FRAME_MAGIC[..4]);

    let (frames, scanned) = scan_frames(&buf);
    assert_eq!(frames.len(), 2);
    assert_eq!(
        scanned, intact,
        "scanning must stop at the torn tail boundary"
    );
}

#[test]
fn flipped_payload_byte_is_caught() {
    let mut encoded = sample_frame().encode();
    let idx = JOURNAL_FRAME_HEADER_LEN + 1;
    encoded[idx] ^= 0xFF;
    assert_eq!(
        JournalFrame::decode(&encoded),
        Err(JournalFrameError::PayloadChecksumMismatch)
    );
}

#[test]
fn flipped_header_byte_is_caught() {
    let mut encoded = sample_frame().encode();
    encoded[12] ^= 0xFF; // a byte inside the epoch field
    assert_eq!(
        JournalFrame::decode(&encoded),
        Err(JournalFrameError::HeaderChecksumMismatch)
    );
}

#[test]
fn truncated_and_bad_magic_are_rejected() {
    assert_eq!(JournalFrame::decode(&[]), Err(JournalFrameError::Truncated));
    assert_eq!(
        JournalFrame::decode(&[0u8; JOURNAL_FRAME_HEADER_LEN]),
        Err(JournalFrameError::BadMagic)
    );

    let mut short_payload = sample_frame().encode();
    short_payload.truncate(short_payload.len() - 1);
    assert_eq!(
        JournalFrame::decode(&short_payload),
        Err(JournalFrameError::PayloadTruncated)
    );
}

#[test]
fn unsupported_future_version_is_rejected() {
    let mut encoded = sample_frame().encode();
    // Bump the version field (offset 8..10) past the current one and repair the
    // header CRC so the version gate — not the CRC — is what rejects it.
    encoded[8..10].copy_from_slice(&(JOURNAL_FRAME_VERSION + 1).to_be_bytes());
    let fixed = crc32(&encoded[0..40]);
    encoded[40..44].copy_from_slice(&fixed.to_be_bytes());
    assert_eq!(
        JournalFrame::decode(&encoded),
        Err(JournalFrameError::UnsupportedVersion(
            JOURNAL_FRAME_VERSION + 1
        ))
    );
}
