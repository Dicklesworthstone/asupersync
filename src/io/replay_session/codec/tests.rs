use super::*;
use crate::io::replay::IoCaptureLimits;
use crate::io::replay_session::{RecordingSession, SessionCaptureLimits};
use crate::io::AsyncWrite;
use crate::time::VirtualClock;
use crate::util::entropy_replay::EntropyCaptureLimits;
use crate::util::DetEntropy;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Debug)]
struct UnusedIo;
impl AsyncWrite for UnusedIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        panic!("an empty session must not invoke I/O")
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("an empty session must not invoke I/O")
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("an empty session must not invoke I/O")
    }
}

fn empty() -> RecordedSession {
    RecordingSession::new(
        UnusedIo, Arc::new(DetEntropy::new(3)), Arc::new(VirtualClock::new()),
        SessionCaptureLimits {
            io: IoCaptureLimits::new(0, 0, 0, 0),
            entropy: EntropyCaptureLimits::new(0, 0, 1),
            clock_observations: 0,
        },
    ).unwrap().into_parts().1.unwrap()
}

fn limits() -> SessionDecodeLimits {
    SessionDecodeLimits {
        max_encoded_bytes: 65_536,
        io: IoTapeDecodeLimits::new(32_768, IoCaptureLimits::new(256, 4096, 4096, 16), 32_768),
        entropy: EntropyTapeDecodeLimits::new(16_384, EntropyCaptureLimits::new(256, 4096, 16), 16_384),
        clock: TimeTapeDecodeLimits::new(16_384, 256, 4096),
    }
}

fn resign(bytes: &mut [u8]) {
    let body = bytes.len() - CHECKSUM;
    let hash = checksum(&bytes[..body]);
    bytes[body..].copy_from_slice(&hash);
}

#[test]
fn complete_session_roundtrip_replays_the_original_nonce_time_protocol() {
    use crate::io::replay_session::tests::{drive, exchange, recorded_exchange};
    let captured = recorded_exchange();
    let encoded = captured.to_canonical_bytes(65_536).unwrap();
    let counts = (captured.io_operations(), captured.entropy_calls(), captured.clock_observations());
    drop(captured);
    let restored = RecordedSession::from_canonical_bytes(encoded.as_ref(), limits()).unwrap();
    assert_eq!((restored.io_operations(), restored.entropy_calls(), restored.clock_observations()), counts);
    assert_eq!(restored.to_canonical_bytes(65_536).unwrap().as_ref(), encoded.as_ref());
    drop(encoded);
    let output = drive(restored.replay().run(100, |p| exchange(p.io, p.entropy, p.clock)))
        .unwrap().unwrap();
    assert_eq!(output, b"yes");
}

#[test]
fn empty_tapes_admit_zero_observations_but_require_envelope_storage() {
    let encoded = empty().to_canonical_bytes(1024).unwrap();
    let mut bounds = limits();
    bounds.max_encoded_bytes = encoded.as_ref().len();
    bounds.io.capture = IoCaptureLimits::new(0, 0, 0, 0);
    bounds.io.max_decoded_bytes = 0;
    bounds.entropy.capture = EntropyCaptureLimits::new(0, 0, 1);
    bounds.clock = TimeTapeDecodeLimits::new(52, 0, 0);
    let replay = RecordedSession::from_canonical_bytes(encoded.as_ref(), bounds).unwrap().replay();
    replay.verify_complete().unwrap();
    bounds.max_encoded_bytes = 0;
    assert!(matches!(RecordedSession::from_canonical_bytes(encoded.as_ref(), bounds), Err(SessionTapeError::EncodedLimit)));
}

#[test]
fn every_truncated_prefix_and_single_bit_mutation_is_refused() {
    let encoded = empty().to_canonical_bytes(1024).unwrap();
    let bytes = encoded.as_ref();
    for length in 0..bytes.len() {
        assert!(RecordedSession::from_canonical_bytes(&bytes[..length], limits()).is_err(), "prefix {length}");
    }
    for index in 0..bytes.len() {
        for bit in 0..8 {
            let mut changed = bytes.to_vec();
            changed[index] ^= 1 << bit;
            assert!(RecordedSession::from_canonical_bytes(&changed, limits()).is_err(), "byte {index} bit {bit}");
        }
    }
}

#[test]
fn exact_output_limit_succeeds_and_one_byte_less_refuses_without_consuming_tapes() {
    let session = empty();
    let encoded = session.to_canonical_bytes(1024).unwrap();
    let length = encoded.as_ref().len();
    assert_eq!(session.to_canonical_bytes(length).unwrap().as_ref(), encoded.as_ref());
    assert!(session.to_canonical_bytes(length - 1).is_err());
    assert!(matches!(session.to_canonical_bytes(0), Err(SessionTapeError::EncodedLimit)));
    assert_eq!(session.to_canonical_bytes(length).unwrap().as_ref(), encoded.as_ref());
    session.replay().verify_complete().unwrap();
}

#[test]
fn missing_extra_and_overflowing_component_lengths_are_rejected() {
    let encoded = empty().to_canonical_bytes(1024).unwrap();
    let mut bytes = encoded.as_ref().to_vec();
    bytes.push(0);
    assert!(matches!(RecordedSession::from_canonical_bytes(&bytes, limits()), Err(SessionTapeError::TrailingData)));
    for offset in [12, 20, 28] {
        let mut bytes = encoded.as_ref().to_vec();
        bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        resign(&mut bytes);
        assert!(matches!(RecordedSession::from_canonical_bytes(&bytes, limits()), Err(SessionTapeError::Overflow)));
    }
    let mut bytes = encoded.as_ref().to_vec();
    let old = read_size(&bytes[12..20]).unwrap();
    bytes[12..20].copy_from_slice(&((old + 1) as u64).to_le_bytes());
    resign(&mut bytes);
    assert!(matches!(RecordedSession::from_canonical_bytes(&bytes, limits()), Err(SessionTapeError::Truncated)));
}

#[test]
fn component_encoded_limits_are_all_checked_before_decoding_first_component() {
    let encoded = empty().to_canonical_bytes(1024).unwrap();
    let mut bytes = encoded.as_ref().to_vec();
    bytes[HEADER] ^= 1; // Invalid first component, even with a valid outer checksum.
    resign(&mut bytes);
    let mut bounds = limits();
    bounds.clock.max_encoded_bytes = 0;
    assert!(matches!(RecordedSession::from_canonical_bytes(&bytes, bounds), Err(SessionTapeError::Clock(TimeTapeError::Limit("encoded bytes")))));
    bounds = limits();
    bounds.entropy.max_encoded_bytes = 0;
    assert!(matches!(RecordedSession::from_canonical_bytes(&bytes, bounds), Err(SessionTapeError::Entropy(EntropyTapeError::Limit("encoded bytes")))));
    bounds = limits();
    bounds.io.max_encoded_bytes = 0;
    assert!(matches!(RecordedSession::from_canonical_bytes(&bytes, bounds), Err(SessionTapeError::Io(IoTapeError::Limit("encoded bytes")))));
}

#[test]
fn nested_checksums_still_refuse_corruption_after_outer_checksum_is_recomputed() {
    let encoded = empty().to_canonical_bytes(1024).unwrap();
    let bytes = encoded.as_ref();
    let io_end = HEADER + read_size(&bytes[12..20]).unwrap();
    let entropy_end = io_end + read_size(&bytes[20..28]).unwrap();
    let clock_end = entropy_end + read_size(&bytes[28..36]).unwrap();
    for (component, end) in [io_end, entropy_end, clock_end].into_iter().enumerate() {
        let mut changed = bytes.to_vec();
        changed[end - 1] ^= 1;
        resign(&mut changed);
        let error = RecordedSession::from_canonical_bytes(&changed, limits()).unwrap_err();
        match component {
            0 => assert_eq!(error, SessionTapeError::Io(IoTapeError::Checksum)),
            1 => assert_eq!(error, SessionTapeError::Entropy(EntropyTapeError::Checksum)),
            _ => assert_eq!(error, SessionTapeError::Clock(TimeTapeError::Checksum)),
        }
    }
}

#[test]
fn each_nested_decoded_storage_budget_is_enforced() {
    let session = crate::io::replay_session::tests::recorded_exchange();
    let encoded = session.to_canonical_bytes(65_536).unwrap();
    for component in 0..3 {
        let mut bounds = limits();
        match component {
            0 => bounds.io.max_decoded_bytes = 0,
            1 => bounds.entropy.max_decoded_bytes = 0,
            _ => bounds.clock.max_decoded_bytes = 0,
        }
        assert!(RecordedSession::from_canonical_bytes(encoded.as_ref(), bounds).is_err());
    }
}

#[test]
fn unknown_envelope_version_and_reordered_components_fail_closed() {
    let encoded = empty().to_canonical_bytes(1024).unwrap();
    let mut changed = encoded.as_ref().to_vec();
    changed[8..12].copy_from_slice(&2_u32.to_le_bytes());
    resign(&mut changed);
    assert!(matches!(RecordedSession::from_canonical_bytes(&changed, limits()), Err(SessionTapeError::Format)));
    let bytes = encoded.as_ref();
    let io_end = HEADER + read_size(&bytes[12..20]).unwrap();
    let entropy_end = io_end + read_size(&bytes[20..28]).unwrap();
    let body_end = bytes.len() - CHECKSUM;
    let io = &bytes[HEADER..io_end];
    let entropy = &bytes[io_end..entropy_end];
    let clock = &bytes[entropy_end..body_end];
    let mut changed = bytes[..12].to_vec();
    put_size(&mut changed, clock.len()).unwrap();
    put_size(&mut changed, entropy.len()).unwrap();
    put_size(&mut changed, io.len()).unwrap();
    changed.extend_from_slice(clock);
    changed.extend_from_slice(entropy);
    changed.extend_from_slice(io);
    changed.extend_from_slice(&[0; CHECKSUM]);
    resign(&mut changed);
    assert!(RecordedSession::from_canonical_bytes(&changed, limits()).is_err());
}

#[test]
fn encoded_debug_is_redacted() {
    let encoded = crate::io::replay_session::tests::recorded_exchange().to_canonical_bytes(65_536).unwrap();
    let debug = format!("{encoded:?}");
    assert!(!debug.contains("yes"));
    assert!(!debug.contains("ASUPSES"));
    assert!(debug.contains("encoded_bytes"));
}

#[test]
#[cfg(target_os = "linux")]
fn linux_empty_session_has_fixed_canonical_bytes() {
    let encoded = empty().to_canonical_bytes(1024).unwrap();
    let hex: String = encoded.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(hex, "41535550534553000100000053000000000000004c00000000000000340000000000000041535550494f000001000000000000000000000000000000000000000000000000000000000000000000000000056c696e7578469adee46738ab72f50c7739df5cd77ec369fb2a938c672e50cb6ac6f110337741535550454e5400010000000100000000000000000000000000000000000000000000000000000000000000497797d6db3c935b1463d4ef9143c389f13840703ff0f50e73f2118a1d2ae93441535550544d000001000000000000000000000063b7a098585b51a2817a1006be39e436d564c5991fb04bf4f72c89f45f0629f61a66d784b08322a7b1f6d8ea85513fdaca8569fbb99dea61bdf6f5fa2e3695af");
}
