use super::*;
use super::super::tests::{capture, drive, receive, empty};
use crate::io::replay::{IoCaptureLimits, IoTapeDecodeLimits};
use crate::io::replay_session::SessionDecodeLimits;
use crate::time::replay::TimeTapeDecodeLimits;
use crate::util::entropy_replay::{EntropyCaptureLimits, EntropyTapeDecodeLimits};

fn limits() -> PolledDecodeLimits {
    PolledDecodeLimits {
        max_encoded_bytes: 1_048_576,
        polls: PollCaptureLimits { max_polls: 256, max_io_polls: 1024, max_write_bytes: 65_536, max_vectored_slices: 16 },
        max_poll_bytes: 262_144,
        ordered: OrderedSessionDecodeLimits {
            max_encoded_bytes: 1_048_576, max_effects: 2048, max_order_bytes: 262_144,
            components: SessionDecodeLimits {
                max_encoded_bytes: 1_048_576,
                io: IoTapeDecodeLimits::new(1_048_576, IoCaptureLimits::new(1024, 65_536, 65_536, 16), 262_144),
                entropy: EntropyTapeDecodeLimits::new(262_144, EntropyCaptureLimits::new(2048, 65_536, 32), 262_144),
                clock: TimeTapeDecodeLimits::new(65_536, 2048, 65_536),
            },
        },
    }
}
fn resign(bytes: &mut [u8]) {
    let end = bytes.len() - CHECKSUM;
    let hash = digest(&bytes[..end]); bytes[end..].copy_from_slice(&hash);
}

#[test]
fn exact_poll_behavior_survives_export_after_original_tapes_are_dropped() {
    let tape = capture();
    let counts = (tape.consumer_polls(), tape.io_polls());
    let encoded = tape.to_canonical_bytes(1_048_576).unwrap(); drop(tape);
    let restored = PolledRecordedSession::from_canonical_bytes(encoded.as_ref(), limits()).unwrap();
    assert_eq!((restored.consumer_polls(), restored.io_polls()), counts);
    assert_eq!(restored.to_canonical_bytes(1_048_576).unwrap().as_ref(), encoded.as_ref());
    drop(encoded);
    let output = drive(restored.run(256, |p| Box::pin(receive(p.io, p.entropy, p.clock)))).unwrap().unwrap().unwrap();
    assert_eq!(output.0, b"yes"); assert_eq!(output.1.len(), 8);
}

#[test]
fn no_silent_downgrade_to_completed_effect_replay() {
    let encoded = empty().to_canonical_bytes(4096).unwrap();
    assert!(OrderedRecordedSession::from_canonical_bytes(encoded.as_ref(), limits().ordered).is_err());
}

#[test]
fn every_truncated_prefix_and_single_bit_mutation_is_refused() {
    let encoded = empty().to_canonical_bytes(4096).unwrap(); let bytes = encoded.as_ref();
    for length in 0..bytes.len() {
        assert!(PolledRecordedSession::from_canonical_bytes(&bytes[..length], limits()).is_err(), "prefix {length}");
    }
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut changed = bytes.to_vec(); changed[i] ^= 1 << bit;
            assert!(PolledRecordedSession::from_canonical_bytes(&changed, limits()).is_err(), "byte {i} bit {bit}");
        }
    }
}

#[test]
fn exact_size_and_storage_boundaries_are_independent() {
    let tape = capture(); let encoded = tape.to_canonical_bytes(1_048_576).unwrap(); let n = encoded.as_ref().len();
    assert!(tape.to_canonical_bytes(n - 1).is_err());
    assert_eq!(tape.to_canonical_bytes(n).unwrap().as_ref(), encoded.as_ref());
    let mut bounds = limits(); bounds.max_encoded_bytes = n;
    bounds.polls.max_polls = tape.consumer_polls(); bounds.polls.max_io_polls = tape.io_polls();
    bounds.max_poll_bytes = tape.consumer_polls() * std::mem::size_of::<PollStep>() + tape.io_polls() * std::mem::size_of::<IoStep>();
    PolledRecordedSession::from_canonical_bytes(encoded.as_ref(), bounds).unwrap();
    for kind in 0..5 {
        let mut bad = bounds;
        match kind { 0 => bad.max_encoded_bytes -= 1, 1 => bad.polls.max_polls -= 1, 2 => bad.polls.max_io_polls -= 1, 3 => bad.max_poll_bytes -= 1, _ => bad.ordered.max_encoded_bytes = 0 }
        assert!(PolledRecordedSession::from_canonical_bytes(encoded.as_ref(), bad).is_err());
    }
}

#[test]
fn incorrect_flags_and_coverage_fail_even_after_resigning() {
    let bytes = capture().to_canonical_bytes(1_048_576).unwrap();
    let io_start = HEADER + size(&bytes.as_ref()[12..20]).unwrap();
    let frames = io_start + size(&bytes.as_ref()[20..28]).unwrap() * IO_BYTES;
    for (offset, value) in [(io_start, 99), (io_start + 1, 2), (frames + 16, 2)] {
        let mut changed = bytes.as_ref().to_vec(); changed[offset] = value; resign(&mut changed);
        assert!(PolledRecordedSession::from_canonical_bytes(&changed, limits()).is_err());
    }
    let mut changed = bytes.as_ref().to_vec();
    changed[io_start + 1] = 0; // Pending read cannot claim a completed clock's slot.
    resign(&mut changed);
    assert!(matches!(PolledRecordedSession::from_canonical_bytes(&changed, limits()), Err(PolledTapeError::Coverage)));
    let mut changed = bytes.as_ref().to_vec();
    changed[frames + 16] = 1; resign(&mut changed); // An early terminal poll is invalid.
    assert!(matches!(PolledRecordedSession::from_canonical_bytes(&changed, limits()), Err(PolledTapeError::Coverage)));
}

#[test]
fn overflow_trailing_bytes_and_nested_corruption_never_expose_prefixes() {
    let encoded = empty().to_canonical_bytes(4096).unwrap();
    let mut changed = encoded.as_ref().to_vec(); changed.push(0);
    assert!(matches!(PolledRecordedSession::from_canonical_bytes(&changed, limits()), Err(PolledTapeError::TrailingData)));
    let mut changed = encoded.as_ref().to_vec(); changed[12..20].copy_from_slice(&u64::MAX.to_le_bytes()); resign(&mut changed);
    let mut bounds = limits(); bounds.ordered.max_encoded_bytes = usize::MAX;
    assert!(matches!(PolledRecordedSession::from_canonical_bytes(&changed, bounds), Err(PolledTapeError::Overflow)));
    let mut changed = encoded.as_ref().to_vec(); changed[HEADER + 9] ^= 1; resign(&mut changed);
    assert!(matches!(PolledRecordedSession::from_canonical_bytes(&changed, limits()), Err(PolledTapeError::Ordered(_))));
}

#[test]
fn zero_poll_frame_count_and_wrong_terminal_checkpoint_are_rejected() {
    let encoded = empty().to_canonical_bytes(4096).unwrap();
    for (offset, value) in [(28, 0_u64), (60, 1_u64)] {
        let mut changed = encoded.as_ref().to_vec(); changed[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); resign(&mut changed);
        assert!(matches!(PolledRecordedSession::from_canonical_bytes(&changed, limits()), Err(PolledTapeError::Coverage)));
    }
}

#[test]
fn encoded_debug_does_not_print_plaintext_or_fingerprints() {
    let encoded = capture().to_canonical_bytes(1_048_576).unwrap();
    let debug = format!("{encoded:?}");
    assert!(debug.contains("encoded_bytes")); assert!(!debug.contains("yes")); assert!(!debug.contains("ASUPPOL"));
}

#[test]
#[cfg(target_os = "linux")]
fn linux_empty_polled_session_has_a_fixed_canonical_digest() {
    let encoded = empty().to_canonical_bytes(4096).unwrap();
    assert_eq!(encoded.as_ref().len(), 456);
    let digest = Sha256::digest(encoded.as_ref());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "90f400c752ced9313172347ba429c676a87d06febd969f63306e16a02044e794");
}
