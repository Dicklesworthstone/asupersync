use super::super::super::tests::{drive, exchange};
use super::super::tests::recorded_exchange;
use super::super::{OrderedRecordingSession, OrderedRunError};
use super::*;
use crate::io::replay::{IoCaptureLimits, IoTapeDecodeLimits};
use crate::io::replay_session::SessionCaptureLimits;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::time::replay::TimeTapeDecodeLimits;
use crate::time::{TimeSource, VirtualClock};
use crate::types::TaskId;
use crate::util::entropy_replay::{EntropyCaptureLimits, EntropyTapeDecodeLimits};
use crate::util::{ArenaIndex, DetEntropy, EntropySource};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

struct UnusedIo;
impl AsyncRead for UnusedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        panic!("unused I/O")
    }
}
impl AsyncWrite for UnusedIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        panic!("unused I/O")
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("unused I/O")
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("unused I/O")
    }
}
fn capture() -> OrderedRecordingSession<UnusedIo, VirtualClock> {
    OrderedRecordingSession::new(
        UnusedIo,
        Arc::new(DetEntropy::new(7)),
        Arc::new(VirtualClock::new()),
        SessionCaptureLimits {
            io: IoCaptureLimits::new(100, 1024, 4096, 8),
            entropy: EntropyCaptureLimits::new(100, 1024, 8),
            clock_observations: 100,
        },
        100,
    )
    .unwrap()
}
fn limits() -> OrderedSessionDecodeLimits {
    OrderedSessionDecodeLimits {
        max_encoded_bytes: 131_072,
        max_effects: 1024,
        max_order_bytes: 65_536,
        components: SessionDecodeLimits {
            max_encoded_bytes: 65_536,
            io: IoTapeDecodeLimits::new(65_536, IoCaptureLimits::new(1024, 8192, 8192, 16), 65_536),
            entropy: EntropyTapeDecodeLimits::new(
                8192,
                EntropyCaptureLimits::new(100, 1024, 8),
                8192,
            ),
            clock: TimeTapeDecodeLimits::new(8192, 100, 800),
        },
    }
}
fn resign(bytes: &mut [u8]) {
    let body = bytes.len() - CHECKSUM;
    let hash = checksum(&bytes[..body]);
    bytes[body..].copy_from_slice(&hash);
}
fn order_start(bytes: &[u8]) -> usize {
    HEADER + size(&bytes[12..20]).unwrap()
}

#[test]
fn persisted_order_replays_original_consumer_after_in_memory_tapes_are_dropped() {
    let tape = recorded_exchange();
    let effects = tape.effects();
    let encoded = tape.to_canonical_bytes(131_072).unwrap();
    drop(tape);
    let decoded = OrderedRecordedSession::from_canonical_bytes(encoded.as_ref(), limits()).unwrap();
    assert_eq!(decoded.effects(), effects);
    assert_eq!(
        decoded.to_canonical_bytes(131_072).unwrap().as_ref(),
        encoded.as_ref()
    );
    drop(encoded);
    assert_eq!(
        drive(
            decoded
                .replay()
                .run(100, |p| exchange(p.io, p.entropy, p.clock))
        )
        .unwrap()
        .unwrap(),
        b"yes"
    );
}

#[test]
fn persistence_cannot_be_silently_downgraded_to_independent_windows() {
    let ordered = recorded_exchange().to_canonical_bytes(131_072).unwrap();
    assert!(matches!(
        RecordedSession::from_canonical_bytes(ordered.as_ref(), limits().components),
        Err(SessionTapeError::Format)
    ));
    let independent = recorded_exchange()
        .components
        .to_canonical_bytes(65_536)
        .unwrap();
    assert!(matches!(
        OrderedRecordedSession::from_canonical_bytes(independent.as_ref(), limits()),
        Err(OrderedSessionTapeError::Format)
    ));
}

#[test]
fn empty_order_accepts_zero_effect_and_order_storage_limits() {
    let encoded = capture()
        .into_parts()
        .1
        .unwrap()
        .to_canonical_bytes(4096)
        .unwrap();
    let mut bounds = limits();
    bounds.max_effects = 0;
    bounds.max_order_bytes = 0;
    OrderedRecordedSession::from_canonical_bytes(encoded.as_ref(), bounds)
        .unwrap()
        .replay()
        .verify_complete()
        .unwrap();
}

#[test]
fn exact_export_limit_and_one_byte_below_preserve_original_tape() {
    let tape = recorded_exchange();
    let bytes = tape.to_canonical_bytes(131_072).unwrap();
    assert_eq!(
        tape.to_canonical_bytes(bytes.as_ref().len())
            .unwrap()
            .as_ref(),
        bytes.as_ref()
    );
    assert!(tape.to_canonical_bytes(bytes.as_ref().len() - 1).is_err());
    assert!(tape.to_canonical_bytes(0).is_err());
    assert_eq!(
        drive(
            tape.replay()
                .run(100, |p| exchange(p.io, p.entropy, p.clock))
        )
        .unwrap()
        .unwrap(),
        b"yes"
    );
}

#[test]
fn every_truncated_prefix_and_bit_flip_is_refused() {
    let encoded = capture()
        .into_parts()
        .1
        .unwrap()
        .to_canonical_bytes(4096)
        .unwrap();
    let bytes = encoded.as_ref();
    for end in 0..bytes.len() {
        assert!(OrderedRecordedSession::from_canonical_bytes(&bytes[..end], limits()).is_err());
    }
    for index in 0..bytes.len() {
        for bit in 0..8 {
            let mut changed = bytes.to_vec();
            changed[index] ^= 1 << bit;
            assert!(OrderedRecordedSession::from_canonical_bytes(&changed, limits()).is_err());
        }
    }
}

#[test]
fn encoded_effect_storage_and_component_bounds_are_independent() {
    let encoded = recorded_exchange().to_canonical_bytes(131_072).unwrap();
    for selected in 0..4 {
        let mut bounds = limits();
        match selected {
            0 => bounds.max_encoded_bytes = 0,
            1 => bounds.max_effects = 0,
            2 => bounds.max_order_bytes = 0,
            _ => bounds.components.max_encoded_bytes = 0,
        }
        assert!(matches!(
            OrderedRecordedSession::from_canonical_bytes(encoded.as_ref(), bounds),
            Err(OrderedSessionTapeError::Limit(_))
        ));
    }
}

#[test]
fn unknown_tags_reserved_fields_and_versions_are_rejected_with_valid_checksums() {
    let encoded = recorded_exchange().to_canonical_bytes(131_072).unwrap();
    let start = order_start(encoded.as_ref());
    for (offset, value) in [(8, 255), (start, 255), (start + 9, 1)] {
        let mut bytes = encoded.as_ref().to_vec();
        bytes[offset] = value;
        resign(&mut bytes);
        assert!(matches!(
            OrderedRecordedSession::from_canonical_bytes(&bytes, limits()),
            Err(OrderedSessionTapeError::Format)
        ));
    }
    let mut bytes = encoded.as_ref().to_vec();
    bytes[start] = 5;
    bytes[start + 1] = 1;
    resign(&mut bytes); // Clock cannot carry a source.
    assert!(matches!(
        OrderedRecordedSession::from_canonical_bytes(&bytes, limits()),
        Err(OrderedSessionTapeError::Format)
    ));
}

#[test]
fn forged_counts_overflows_and_trailing_data_never_allocate_unbounded_order() {
    let encoded = capture()
        .into_parts()
        .1
        .unwrap()
        .to_canonical_bytes(4096)
        .unwrap();
    let mut bounds = limits();
    bounds.max_effects = usize::MAX;
    bounds.max_order_bytes = usize::MAX;
    bounds.components.max_encoded_bytes = usize::MAX;
    for offset in [12, 20] {
        let mut bytes = encoded.as_ref().to_vec();
        bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        resign(&mut bytes);
        assert!(matches!(
            OrderedRecordedSession::from_canonical_bytes(&bytes, bounds),
            Err(OrderedSessionTapeError::Overflow)
        ));
    }
    let mut bytes = encoded.as_ref().to_vec();
    bytes.push(0);
    assert!(matches!(
        OrderedRecordedSession::from_canonical_bytes(&bytes, limits()),
        Err(OrderedSessionTapeError::TrailingData)
    ));
}

#[test]
fn order_domain_counts_must_cover_all_component_observations() {
    let encoded = recorded_exchange().to_canonical_bytes(131_072).unwrap();
    let mut bytes = encoded.as_ref().to_vec();
    let start = order_start(&bytes);
    assert_eq!(bytes[start], 6); // Replace entropy with an extra clock observation.
    bytes[start] = 5;
    resign(&mut bytes);
    assert!(matches!(
        OrderedRecordedSession::from_canonical_bytes(&bytes, limits()),
        Err(OrderedSessionTapeError::Coverage)
    ));
}

#[test]
fn fork_children_must_be_created_once_in_order_from_existing_sources() {
    let recording = capture();
    let a = recording
        .entropy()
        .fork(TaskId::from_arena(ArenaIndex::new(1, 3)));
    a.next_u64();
    recording.clock().now();
    let encoded = recording
        .into_parts()
        .1
        .unwrap()
        .to_canonical_bytes(8192)
        .unwrap();
    let start = order_start(encoded.as_ref());
    for (offset, value) in [(start + 1, 1), (start + 9, 2), (start + ENTRY_BYTES + 1, 2)] {
        let mut bytes = encoded.as_ref().to_vec();
        bytes[offset] = value;
        resign(&mut bytes);
        assert!(matches!(
            OrderedRecordedSession::from_canonical_bytes(&bytes, limits()),
            Err(OrderedSessionTapeError::Coverage)
        ));
    }
}

#[test]
fn recomputing_outer_checksum_does_not_bypass_component_integrity() {
    let encoded = recorded_exchange().to_canonical_bytes(131_072).unwrap();
    let mut bytes = encoded.as_ref().to_vec();
    let start = order_start(&bytes);
    bytes[start - 1] ^= 1;
    resign(&mut bytes);
    assert!(matches!(
        OrderedRecordedSession::from_canonical_bytes(&bytes, limits()),
        Err(OrderedSessionTapeError::Components(
            SessionTapeError::Checksum
        ))
    ));
}

#[test]
fn edited_io_category_cannot_be_accepted_as_a_successful_consumer_result() {
    let encoded = recorded_exchange().to_canonical_bytes(131_072).unwrap();
    let mut bytes = encoded.as_ref().to_vec();
    let start = order_start(&bytes);
    assert_eq!(bytes[start + 2 * ENTRY_BYTES], 1);
    bytes[start + 2 * ENTRY_BYTES] = 3;
    resign(&mut bytes); // Write -> flush; counts alone still match.
    let replay = OrderedRecordedSession::from_canonical_bytes(&bytes, limits())
        .unwrap()
        .replay();
    assert!(matches!(
        drive(replay.run(100, |p| exchange(p.io, p.entropy, p.clock))),
        Err(OrderedRunError::Replay(_))
    ));
}

#[test]
fn encoded_debug_excludes_payload_and_order_contents() {
    let encoded = recorded_exchange().to_canonical_bytes(131_072).unwrap();
    let debug = format!("{encoded:?}");
    assert!(debug.contains("encoded_bytes"));
    assert!(!debug.contains("yes"));
    assert!(!debug.contains("ASUPORD"));
}

#[test]
#[cfg(target_os = "linux")]
fn empty_linux_envelope_has_a_fixed_full_body_checksum() {
    let encoded = capture()
        .into_parts()
        .1
        .unwrap()
        .to_canonical_bytes(4096)
        .unwrap();
    assert_eq!(encoded.as_ref().len(), 339);
    let digest = &encoded.as_ref()[encoded.as_ref().len() - CHECKSUM..];
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex,
        "148142ca85e6168c1a047c71f0d09183295398a25e326368ad1141348c1650b5"
    );
}
