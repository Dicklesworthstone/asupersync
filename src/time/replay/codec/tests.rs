use super::*;
use crate::time::replay::{RecordingTimeSource, TimeReplayError};
use crate::time::{TimeSource, TimerDriver, TimerDriverHandle};
use crate::types::Time;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Wake, Waker};

const LIMITS: TimeTapeDecodeLimits = TimeTapeDecodeLimits::new(4096, 128, 1024);

fn encode(samples: &[u64]) -> TimeTapeBytes {
    assert!(samples.windows(2).all(|pair| pair[0] <= pair[1]));
    TimeTape {
        samples: samples.to_vec(),
    }
    .to_canonical_bytes(LIMITS.max_encoded_bytes)
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::new();
    for byte in bytes {
        write!(text, "{byte:02x}").unwrap();
    }
    text
}

fn resign(bytes: &mut [u8]) {
    let body_len = bytes.len() - CHECKSUM_BYTES;
    let digest = checksum(&bytes[..body_len]);
    bytes[body_len..].copy_from_slice(&digest);
}

#[test]
fn v1_empty_tape_matches_independent_golden() {
    assert_eq!(
        hex(encode(&[]).as_ref()),
        concat!(
            "41535550544d0000010000000000000000000000",
            "63b7a098585b51a2817a1006be39e436d564c5991fb04bf4f72c89f45f0629f6"
        )
    );
}

#[test]
fn v1_full_range_and_duplicate_observations_match_independent_golden() {
    assert_eq!(
        hex(encode(&[0, 1, 1, u64::MAX]).as_ref()),
        concat!(
            "41535550544d0000010000000400000000000000",
            "000000000000000001000000000000000100000000000000ffffffffffffffff",
            "72c75566bffbd24a5f0c6771d5ef6263f1ff4752f0eac83888b7de9e8c024375"
        )
    );
}

#[test]
fn round_trip_is_canonical_and_replay_remains_fail_closed() {
    let samples = [0, 7, 7, 987_654_321, u64::MAX];
    let bytes = encode(&samples);
    let tape = TimeTape::from_canonical_bytes(bytes.as_ref(), LIMITS).unwrap();
    assert_eq!(tape.observations(), samples.len());
    assert_eq!(
        tape.to_canonical_bytes(4096).unwrap().as_ref(),
        bytes.as_ref()
    );
    let replay = tape.replay();
    for sample in samples {
        assert_eq!(replay.try_now(), Ok(Time::from_nanos(sample)));
    }
    assert_eq!(replay.verify_complete(), Ok(()));
    let expected = TimeReplayError::Exhausted {
        index: samples.len(),
    };
    assert_eq!(replay.try_now(), Err(expected));
    assert_eq!(replay.verify_complete(), Err(expected));
}

#[test]
fn empty_tape_requires_no_observation_or_decoded_storage_budget() {
    let bytes = encode(&[]);
    let limits = TimeTapeDecodeLimits::new(bytes.as_ref().len(), 0, 0);
    let tape = TimeTape::from_canonical_bytes(bytes.as_ref(), limits).unwrap();
    assert_eq!(tape.observations(), 0);
    assert_eq!(tape.replay().verify_complete(), Ok(()));
}

#[test]
fn import_enforces_each_independent_limit_at_exact_boundary() {
    let bytes = encode(&[10, 20]);
    let len = bytes.as_ref().len();
    assert_eq!(len, 68);
    assert!(
        TimeTape::from_canonical_bytes(bytes.as_ref(), TimeTapeDecodeLimits::new(len, 2, 16))
            .is_ok()
    );
    for (limits, expected) in [
        (
            TimeTapeDecodeLimits::new(len - 1, 2, 16),
            TimeTapeError::Limit("encoded bytes"),
        ),
        (
            TimeTapeDecodeLimits::new(len, 1, 16),
            TimeTapeError::Limit("observations"),
        ),
        (
            TimeTapeDecodeLimits::new(len, 2, 15),
            TimeTapeError::Limit("decoded bytes"),
        ),
    ] {
        assert_eq!(
            TimeTape::from_canonical_bytes(bytes.as_ref(), limits).unwrap_err(),
            expected
        );
    }
}

#[test]
fn export_limit_does_not_consume_or_corrupt_original_tape() {
    let tape = TimeTape {
        samples: vec![10, 20],
    };
    for limit in [0, 51, 67] {
        assert_eq!(
            tape.to_canonical_bytes(limit).unwrap_err(),
            TimeTapeError::Limit("encoded bytes")
        );
        assert_eq!(tape.observations(), 2);
    }
    assert_eq!(tape.to_canonical_bytes(68).unwrap().as_ref().len(), 68);
    let replay = tape.replay();
    assert_eq!(replay.try_now(), Ok(Time::from_nanos(10)));
    assert_eq!(replay.try_now(), Ok(Time::from_nanos(20)));
    assert_eq!(replay.verify_complete(), Ok(()));
}

#[test]
fn every_truncated_prefix_is_refused() {
    let encoded = encode(&[0, 1, 1, u64::MAX]);
    let bytes = encoded.as_ref();
    for end in 0..bytes.len() {
        assert_eq!(
            TimeTape::from_canonical_bytes(&bytes[..end], LIMITS).unwrap_err(),
            TimeTapeError::Truncated,
            "prefix length {end}"
        );
    }
}

#[test]
fn every_single_bit_corruption_is_refused() {
    let encoded = encode(&[0, 1, 1, u64::MAX]);
    for index in 0..encoded.as_ref().len() {
        for bit in 0..8 {
            let mut bytes = encoded.as_ref().to_vec();
            bytes[index] ^= 1 << bit;
            assert!(
                TimeTape::from_canonical_bytes(&bytes, LIMITS).is_err(),
                "accepted corrupted byte {index}, bit {bit}"
            );
        }
    }
}

#[test]
fn unsupported_magic_and_version_fail_even_with_a_matching_checksum() {
    for offset in [0, 8] {
        let mut bytes = encode(&[10]).as_ref().to_vec();
        bytes[offset] ^= 0x80;
        resign(&mut bytes);
        assert_eq!(
            TimeTape::from_canonical_bytes(&bytes, LIMITS).unwrap_err(),
            TimeTapeError::Format
        );
    }
}

#[test]
fn mismatched_counts_cannot_admit_a_prefix_or_invent_observations() {
    for (count, error) in [
        (1_u64, TimeTapeError::TrailingData),
        (3, TimeTapeError::Truncated),
    ] {
        let mut bytes = encode(&[10, 20]).as_ref().to_vec();
        bytes[12..HEADER_BYTES].copy_from_slice(&count.to_le_bytes());
        resign(&mut bytes);
        assert_eq!(
            TimeTape::from_canonical_bytes(&bytes, LIMITS).unwrap_err(),
            error
        );
    }
}

#[test]
fn trailing_data_and_concatenated_tapes_are_not_silently_ignored() {
    let encoded = encode(&[10, 20]);
    for suffix in [&[0_u8][..], encoded.as_ref()] {
        let mut bytes = encoded.as_ref().to_vec();
        bytes.extend_from_slice(suffix);
        assert_eq!(
            TimeTape::from_canonical_bytes(&bytes, LIMITS).unwrap_err(),
            TimeTapeError::TrailingData
        );
    }
    // Even a correctly re-signed body cannot hide bytes outside the count.
    let mut bytes = encoded.as_ref()[..encoded.as_ref().len() - CHECKSUM_BYTES].to_vec();
    bytes.extend_from_slice(&[0; SAMPLE_BYTES]);
    bytes.extend_from_slice(&[0; CHECKSUM_BYTES]);
    resign(&mut bytes);
    assert_eq!(
        TimeTape::from_canonical_bytes(&bytes, LIMITS).unwrap_err(),
        TimeTapeError::TrailingData
    );
}

#[test]
fn backwards_observation_is_rejected_after_checksum_validation() {
    let mut bytes = encode(&[10, 20]).as_ref().to_vec();
    bytes[HEADER_BYTES + SAMPLE_BYTES..HEADER_BYTES + 2 * SAMPLE_BYTES]
        .copy_from_slice(&9_u64.to_le_bytes());
    assert_eq!(
        TimeTape::from_canonical_bytes(&bytes, LIMITS).unwrap_err(),
        TimeTapeError::Checksum
    );
    resign(&mut bytes);
    assert_eq!(
        TimeTape::from_canonical_bytes(&bytes, LIMITS).unwrap_err(),
        TimeTapeError::NonMonotonic { index: 1 }
    );
}

#[test]
fn checksum_requires_the_clock_tape_domain() {
    let mut bytes = encode(&[10, 20]).as_ref().to_vec();
    let body_len = bytes.len() - CHECKSUM_BYTES;
    let mut hash = Sha256::new();
    hash.update(b"asupersync.io-tape.v1");
    hash.update(&bytes[..body_len]);
    bytes[body_len..].copy_from_slice(&hash.finalize());
    assert_eq!(
        TimeTape::from_canonical_bytes(&bytes, LIMITS).unwrap_err(),
        TimeTapeError::Checksum
    );
}

#[test]
fn malicious_counts_and_encoded_size_overflow_fail_without_allocation() {
    let mut bytes = encode(&[]).as_ref().to_vec();
    bytes[12..HEADER_BYTES].copy_from_slice(&u64::MAX.to_le_bytes());
    resign(&mut bytes);
    assert_eq!(
        TimeTape::from_canonical_bytes(
            &bytes,
            TimeTapeDecodeLimits::new(usize::MAX, usize::MAX, usize::MAX),
        )
        .unwrap_err(),
        TimeTapeError::Overflow
    );
    assert_eq!(encoded_size(usize::MAX), Err(TimeTapeError::Overflow));
    assert_eq!(
        encoded_size(usize::MAX - HEADER_BYTES),
        Err(TimeTapeError::Overflow)
    );
}

#[test]
fn decoding_owns_samples_and_debug_omits_timestamps() {
    let encoded = encode(&[987_654_321]);
    assert_eq!(
        format!("{encoded:?}"),
        "TimeTapeBytes { encoded_bytes: 60, .. }"
    );
    let mut bytes = encoded.as_ref().to_vec();
    let tape = TimeTape::from_canonical_bytes(&bytes, LIMITS).unwrap();
    bytes.fill(0);
    assert_eq!(tape.replay().try_now(), Ok(Time::from_nanos(987_654_321)));
}

#[test]
fn persisted_capture_replays_real_timer_driver_after_source_is_dropped() {
    struct AdjustableClock(AtomicU64);
    impl TimeSource for AdjustableClock {
        fn now(&self) -> Time {
            Time::from_nanos(self.0.load(Ordering::SeqCst))
        }
    }
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let source = Arc::new(AdjustableClock(AtomicU64::new(0)));
    let recorder = Arc::new(RecordingTimeSource::new(Arc::clone(&source), 64));
    let driver = TimerDriverHandle::new(Arc::new(TimerDriver::with_clock(Arc::clone(&recorder))));
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let _timer = driver.register(Time::from_secs(1), Waker::from(Arc::clone(&wakes)));
    assert_eq!(driver.process_timers(), 0);
    source.0.store(2_000_000_000, Ordering::SeqCst);
    assert_eq!(driver.process_timers(), 1);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    assert_eq!(driver.pending_count(), 0);
    drop(driver);
    let tape = recorder.finish().unwrap();
    let encoded = tape.to_canonical_bytes(4096).unwrap();
    drop(tape);
    drop(recorder);
    drop(source);

    let restored = TimeTape::from_canonical_bytes(encoded.as_ref(), LIMITS).unwrap();
    drop(encoded);
    let replay = Arc::new(restored.replay());
    let driver = TimerDriverHandle::new(Arc::new(TimerDriver::with_clock(Arc::clone(&replay))));
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let _timer = driver.register(Time::from_secs(1), Waker::from(Arc::clone(&wakes)));
    assert_eq!(driver.process_timers(), 0);
    assert_eq!(driver.process_timers(), 1);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    assert_eq!(driver.pending_count(), 0);
    assert_eq!(replay.verify_complete(), Ok(()));
}
