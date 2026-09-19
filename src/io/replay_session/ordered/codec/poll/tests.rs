use super::super::super::{OrderedRecordingSession, OrderedRunError, PendingIoCaptureLimits};
use super::super::{SessionDecodeLimits, SessionTapeError};
use super::*;
use crate::io::replay::{IoCaptureLimits, IoTapeDecodeLimits};
use crate::io::replay_session::SessionCaptureLimits;
use crate::io::replay_session::ordered::pending_tests::{capture, recorded_exchange};
use crate::io::replay_session::tests::{drive, exchange};
use crate::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::time::VirtualClock;
use crate::time::replay::TimeTapeDecodeLimits;
use crate::util::DetEntropy;
use crate::util::entropy_replay::{EntropyCaptureLimits, EntropyTapeDecodeLimits};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

fn limits() -> OrderedSessionDecodeLimits {
    OrderedSessionDecodeLimits {
        max_encoded_bytes: 262_144,
        max_effects: 2048,
        max_order_bytes: 262_144,
        components: SessionDecodeLimits {
            max_encoded_bytes: 131_072,
            io: IoTapeDecodeLimits::new(
                131_072,
                IoCaptureLimits::new(1024, 8192, 8192, 16),
                131_072,
            ),
            entropy: EntropyTapeDecodeLimits::new(
                8192,
                EntropyCaptureLimits::new(100, 1024, 8),
                8192,
            ),
            clock: TimeTapeDecodeLimits::new(8192, 100, 800),
        },
    }
}
fn cx() -> Context<'static> {
    Context::from_waker(Waker::noop())
}
fn resign(bytes: &mut [u8]) {
    let body_end = bytes.len() - CHECKSUM;
    let digest = checksum(&bytes[..body_end]);
    bytes[body_end..].copy_from_slice(&digest);
}
fn order_start(bytes: &[u8]) -> usize {
    HEADER + size(&bytes[12..20]).unwrap()
}

fn pending_write() -> OrderedSessionBytes {
    let mut recording = capture();
    assert!(
        Pin::new(recording.io())
            .poll_write(&mut cx(), b"secret")
            .is_pending()
    );
    recording
        .into_parts()
        .1
        .unwrap()
        .to_canonical_bytes(8192)
        .unwrap()
}
fn pending_read() -> OrderedSessionBytes {
    let mut recording = capture();
    assert!(
        Pin::new(recording.io())
            .poll_read(&mut cx(), &mut ReadBuf::new(&mut [0; 2]))
            .is_pending()
    );
    recording
        .into_parts()
        .1
        .unwrap()
        .to_canonical_bytes(8192)
        .unwrap()
}

#[test]
fn roundtrip_restores_pending_boundaries_and_the_same_borrowing_consumer() {
    let tape = recorded_exchange();
    let counts = (tape.effects(), tape.pending_io_polls());
    let encoded = tape.to_canonical_bytes(262_144).unwrap();
    assert_eq!(&encoded.as_ref()[8..12], &2_u32.to_le_bytes());
    drop(tape);
    let decoded =
        OrderedRecordedSession::from_poll_aware_bytes(encoded.as_ref(), limits()).unwrap();
    assert!(decoded.is_poll_aware());
    assert_eq!((decoded.effects(), decoded.pending_io_polls()), counts);
    assert_eq!(
        decoded.to_canonical_bytes(262_144).unwrap().as_ref(),
        encoded.as_ref()
    );
    drop(encoded);
    assert_eq!(
        drive(
            decoded
                .replay()
                .run(128, |p| exchange(p.io, p.entropy, p.clock))
        )
        .unwrap()
        .unwrap(),
        b"yes"
    );
}

#[test]
fn strict_import_refuses_v1_and_independent_sessions_instead_of_downgrading() {
    let old = crate::io::replay_session::ordered::tests::recorded_exchange();
    let encoded = old.to_canonical_bytes(262_144).unwrap();
    assert_eq!(&encoded.as_ref()[8..12], &1_u32.to_le_bytes());
    assert!(matches!(
        OrderedRecordedSession::from_poll_aware_bytes(encoded.as_ref(), limits()),
        Err(OrderedSessionTapeError::Format)
    ));
    let old_decoded =
        OrderedRecordedSession::from_canonical_bytes(encoded.as_ref(), limits()).unwrap();
    assert!(!old_decoded.is_poll_aware());
    assert_eq!(
        old_decoded.to_canonical_bytes(262_144).unwrap().as_ref(),
        encoded.as_ref()
    );
    let independent = old.components.to_canonical_bytes(131_072).unwrap();
    assert!(matches!(
        OrderedRecordedSession::from_poll_aware_bytes(independent.as_ref(), limits()),
        Err(OrderedSessionTapeError::Format)
    ));
    assert!(matches!(
        RecordedSession::from_canonical_bytes(pending_write().as_ref(), limits().components),
        Err(SessionTapeError::Format)
    ));
}

#[test]
fn strict_empty_window_stays_v2_with_zero_count_and_order_storage() {
    let bytes = capture()
        .into_parts()
        .1
        .unwrap()
        .to_canonical_bytes(4096)
        .unwrap();
    let mut bounds = limits();
    bounds.max_effects = 0;
    bounds.max_order_bytes = 0;
    let decoded = OrderedRecordedSession::from_canonical_bytes(bytes.as_ref(), bounds).unwrap();
    assert!(decoded.is_poll_aware());
    assert_eq!(decoded.effects(), 0);
    assert_eq!(decoded.pending_io_polls(), 0);
    decoded.replay().verify_complete().unwrap();
}

#[test]
fn every_truncated_prefix_and_single_bit_mutation_is_refused() {
    let encoded = pending_write();
    let bytes = encoded.as_ref();
    for end in 0..bytes.len() {
        assert!(
            OrderedRecordedSession::from_poll_aware_bytes(&bytes[..end], limits()).is_err(),
            "prefix {end}"
        );
    }
    for index in 0..bytes.len() {
        for bit in 0..8 {
            let mut changed = bytes.to_vec();
            changed[index] ^= 1 << bit;
            assert!(
                OrderedRecordedSession::from_poll_aware_bytes(&changed, limits()).is_err(),
                "byte {index} bit {bit}"
            );
        }
    }
}

#[test]
fn exact_export_budget_preserves_the_source_and_one_byte_less_refuses() {
    let tape = recorded_exchange();
    let bytes = tape.to_canonical_bytes(262_144).unwrap();
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
                .run(128, |p| exchange(p.io, p.entropy, p.clock))
        )
        .unwrap()
        .unwrap(),
        b"yes"
    );
}

#[test]
fn encoded_effect_storage_and_nested_limits_are_independent() {
    let bytes = pending_write();
    for selected in 0..4 {
        let mut bounds = limits();
        match selected {
            0 => bounds.max_encoded_bytes = 0,
            1 => bounds.max_effects = 0,
            2 => bounds.max_order_bytes = 0,
            _ => bounds.components.max_encoded_bytes = 0,
        }
        assert!(matches!(
            OrderedRecordedSession::from_poll_aware_bytes(bytes.as_ref(), bounds),
            Err(OrderedSessionTapeError::Limit(_))
        ));
    }
    let mut bounds = limits();
    bounds.max_order_bytes = std::mem::size_of::<Entry>();
    OrderedRecordedSession::from_poll_aware_bytes(bytes.as_ref(), bounds).unwrap();
    bounds.max_order_bytes -= 1;
    assert!(matches!(
        OrderedRecordedSession::from_poll_aware_bytes(bytes.as_ref(), bounds),
        Err(OrderedSessionTapeError::Limit("order bytes"))
    ));
}

#[test]
fn pending_hashing_limits_are_admitted_before_decoding_nested_components() {
    let bytes = pending_write();
    let mut changed = bytes.as_ref().to_vec();
    changed[HEADER] ^= 1; // Invalid nested magic; pending budget must win first.
    resign(&mut changed);
    let mut bounds = limits();
    bounds.components.io.capture.max_write_bytes = 5;
    assert!(matches!(
        OrderedRecordedSession::from_poll_aware_bytes(&changed, bounds),
        Err(OrderedSessionTapeError::Limit("pending write bytes"))
    ));
    bounds.components.io.capture.max_write_bytes = 6;
    assert!(matches!(
        OrderedRecordedSession::from_poll_aware_bytes(&changed, bounds),
        Err(OrderedSessionTapeError::Components(_))
    ));
    OrderedRecordedSession::from_poll_aware_bytes(bytes.as_ref(), bounds).unwrap();
}

#[test]
fn pending_vector_count_is_bounded_without_allocating_or_visiting_slices() {
    let mut recording = capture();
    let bufs = [
        io::IoSlice::new(b""),
        io::IoSlice::new(b""),
        io::IoSlice::new(b""),
    ];
    assert!(
        Pin::new(recording.io())
            .poll_write_vectored(&mut cx(), &bufs)
            .is_pending()
    );
    let bytes = recording
        .into_parts()
        .1
        .unwrap()
        .to_canonical_bytes(8192)
        .unwrap();
    let mut bounds = limits();
    bounds.components.io.capture.max_vectored_slices = 2;
    assert!(matches!(
        OrderedRecordedSession::from_poll_aware_bytes(bytes.as_ref(), bounds),
        Err(OrderedSessionTapeError::Limit("pending vectored slices"))
    ));
    bounds.components.io.capture.max_vectored_slices = 3;
    let mut replay = OrderedRecordedSession::from_poll_aware_bytes(bytes.as_ref(), bounds)
        .unwrap()
        .replay();
    assert!(
        Pin::new(replay.inputs().io)
            .poll_write_vectored(&mut cx(), &bufs)
            .is_pending()
    );
    replay.verify_complete().unwrap();
}

#[test]
fn pending_flags_tags_and_reserved_fields_are_validated_with_correct_checksums() {
    let encoded = pending_write();
    let start = order_start(encoded.as_ref());
    for (offset, byte) in [
        (8, 255),
        (start, 255),
        (start + 1, 1),
        (start + 9, 1),
        (start + 17, 2),
        (start + 17, 0),
        (start, 5),
    ] {
        let mut bytes = encoded.as_ref().to_vec();
        bytes[offset] = byte;
        resign(&mut bytes);
        assert!(
            matches!(
                OrderedRecordedSession::from_poll_aware_bytes(&bytes, limits()),
                Err(OrderedSessionTapeError::Format)
            ),
            "offset {offset} value {byte}"
        );
    }
    let encoded = pending_read();
    let start = order_start(encoded.as_ref());
    for offset in [start + 26, start + 34] {
        // Read has neither slices nor digest.
        let mut bytes = encoded.as_ref().to_vec();
        bytes[offset] = 1;
        resign(&mut bytes);
        assert!(matches!(
            OrderedRecordedSession::from_poll_aware_bytes(&bytes, limits()),
            Err(OrderedSessionTapeError::Format)
        ));
    }
}

#[test]
fn nonpending_extension_bytes_cannot_smuggle_a_hidden_attempt() {
    let encoded = recorded_exchange().to_canonical_bytes(262_144).unwrap();
    let start = order_start(encoded.as_ref()); // Entropy completion is first.
    assert_eq!(encoded.as_ref()[start + 17], 0);
    for offset in [start + 18, start + 26, start + 65] {
        let mut changed = encoded.as_ref().to_vec();
        changed[offset] = 1;
        resign(&mut changed);
        assert!(matches!(
            OrderedRecordedSession::from_poll_aware_bytes(&changed, limits()),
            Err(OrderedSessionTapeError::Format)
        ));
    }
}

#[test]
fn pending_digest_substitution_cannot_be_accepted_as_a_consumer_result() {
    let encoded = pending_write();
    let mut bytes = encoded.as_ref().to_vec();
    let start = order_start(&bytes);
    bytes[start + 34] ^= 1;
    resign(&mut bytes); // Checksums are not producer authentication.
    let replay = OrderedRecordedSession::from_poll_aware_bytes(&bytes, limits())
        .unwrap()
        .replay();
    let result = drive(replay.run(4, |p| {
        Box::pin(async move {
            let _ = p.io.write(b"secret").await;
        })
    }));
    assert!(matches!(result, Err(OrderedRunError::Replay(_))));
}

#[test]
fn changed_ready_pending_coverage_cannot_drop_recorded_io_completions() {
    let encoded = recorded_exchange().to_canonical_bytes(262_144).unwrap();
    let mut bytes = encoded.as_ref().to_vec();
    let start = order_start(&bytes);
    let index = bytes[start..bytes.len() - CHECKSUM]
        .chunks_exact(POLL_ENTRY_BYTES)
        .position(|entry| entry[0] == 3 && entry[17] == 0)
        .unwrap(); // Ready flush.
    bytes[start + index * POLL_ENTRY_BYTES + 17] = 1;
    resign(&mut bytes);
    assert!(matches!(
        OrderedRecordedSession::from_poll_aware_bytes(&bytes, limits()),
        Err(OrderedSessionTapeError::Coverage)
    ));
}

#[test]
fn huge_counts_overflows_trailing_data_and_nested_corruption_fail_closed() {
    let encoded = pending_write();
    let mut bounds = limits();
    bounds.max_effects = usize::MAX;
    bounds.max_order_bytes = usize::MAX;
    bounds.components.max_encoded_bytes = usize::MAX;
    for offset in [12, 20] {
        let mut bytes = encoded.as_ref().to_vec();
        bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        resign(&mut bytes);
        assert!(matches!(
            OrderedRecordedSession::from_poll_aware_bytes(&bytes, bounds),
            Err(OrderedSessionTapeError::Overflow)
        ));
    }
    let mut bytes = encoded.as_ref().to_vec();
    bytes.push(0);
    assert!(matches!(
        OrderedRecordedSession::from_poll_aware_bytes(&bytes, limits()),
        Err(OrderedSessionTapeError::TrailingData)
    ));
    let mut bytes = encoded.as_ref().to_vec();
    let start = order_start(&bytes);
    bytes[start - 1] ^= 1;
    resign(&mut bytes);
    assert!(matches!(
        OrderedRecordedSession::from_poll_aware_bytes(&bytes, limits()),
        Err(OrderedSessionTapeError::Components(
            SessionTapeError::Checksum
        ))
    ));
}

#[test]
fn pending_budget_can_be_exhausted_without_any_completed_io() {
    // Separately dropped pending writes: completed components stay empty.
    struct AlwaysPending;
    impl AsyncWrite for AlwaysPending {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }
    let mut recording = OrderedRecordingSession::new_with_pending_io(
        AlwaysPending,
        Arc::new(DetEntropy::new(42)),
        Arc::new(VirtualClock::new()),
        SessionCaptureLimits {
            io: IoCaptureLimits::new(0, 0, 0, 0),
            entropy: EntropyCaptureLimits::new(0, 0, 1),
            clock_observations: 0,
        },
        8,
        PendingIoCaptureLimits::new(8, 8, 0),
    )
    .unwrap();
    for _ in 0..2 {
        assert!(
            Pin::new(recording.io())
                .poll_write(&mut cx(), b"abc")
                .is_pending()
        );
    }
    let bytes = recording
        .into_parts()
        .1
        .unwrap()
        .to_canonical_bytes(8192)
        .unwrap();
    let mut bounds = limits();
    bounds.components.io.capture.max_write_bytes = 5;
    assert!(matches!(
        OrderedRecordedSession::from_poll_aware_bytes(bytes.as_ref(), bounds),
        Err(OrderedSessionTapeError::Limit("pending write bytes"))
    ));
}

#[test]
fn sensitive_encoding_debug_omits_pending_request_and_digest() {
    let encoded = pending_write();
    let debug = format!("{encoded:?}");
    assert!(!debug.contains("secret"));
    assert!(!debug.contains("digest"));
    assert!(debug.contains("encoded_bytes"));
}

#[test]
#[cfg(target_os = "linux")]
fn empty_v2_linux_encoding_has_a_fixed_checksum_without_v1_downgrade() {
    let bytes = capture()
        .into_parts()
        .1
        .unwrap()
        .to_canonical_bytes(4096)
        .unwrap();
    assert_eq!(bytes.as_ref().len(), 339);
    let digest = &bytes.as_ref()[bytes.as_ref().len() - CHECKSUM..];
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex,
        "5b2eedbb29655d09326ed1792ed1966ac871d8287ac81bb40733fb378d55b0f5"
    );
}
