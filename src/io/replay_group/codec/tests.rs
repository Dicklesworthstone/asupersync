use super::*;
use crate::io::replay::IoCaptureLimits;
use crate::io::replay_group::{IoGroupCaptureLimits, IoGroupCompletionError, IoGroupReplayError, IoRecordingGroup};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::{io, pin::Pin, task::{Context, Poll, Waker}};

struct Sink;
impl AsyncWrite for Sink {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> { Poll::Ready(Ok(buf.len())) }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}
fn bounds() -> IoGroupDecodeLimits {
    IoGroupDecodeLimits { max_encoded_bytes: 16_384, max_streams: 4, max_events: 32, max_group_bytes: 8192,
        per_stream: IoTapeDecodeLimits::new(8192, IoCaptureLimits::new(16, 64, 64, 4), 4096) }
}
fn captured() -> RecordedIoGroup {
    let group = IoRecordingGroup::new(IoGroupCaptureLimits { max_streams: 2, max_events: 8, per_stream: IoCaptureLimits::new(4, 0, 16, 0) });
    let mut a = group.register(3, Sink).unwrap(); let mut b = group.register(5, Sink).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(Pin::new(&mut a).poll_write(&mut cx, b"a"), Poll::Ready(Ok(1))));
    assert!(matches!(Pin::new(&mut b).poll_write(&mut cx, b"b"), Poll::Ready(Ok(1))));
    a.into_inner(); b.into_inner(); group.finish().unwrap()
}
fn replay(tape: RecordedIoGroup) {
    let replay = tape.replay(); let mut a = replay.open(3).unwrap(); let mut b = replay.open(5).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut b).poll_write(&mut cx, b"b").is_pending());
    assert!(matches!(Pin::new(&mut a).poll_write(&mut cx, b"a"), Poll::Ready(Ok(1))));
    assert!(matches!(Pin::new(&mut b).poll_write(&mut cx, b"b"), Poll::Ready(Ok(1))));
    replay.verify_complete().unwrap();
}
fn resign(bytes: &mut [u8]) {
    let end = bytes.len() - CHECKSUM; let digest = checksum(&bytes[..end]); bytes[end..].copy_from_slice(&digest);
}
fn positions(bytes: &[u8]) -> (usize, usize) {
    let second = HEADER + 16 + count(bytes, HEADER + 8).unwrap();
    let order = second + 16 + count(bytes, second + 8).unwrap();
    (second, order)
}

#[test]
fn bounded_roundtrip_retains_stream_identity_and_cross_stream_order() {
    let tape = captured(); let bytes = tape.to_canonical_bytes(16_384).unwrap();
    let decoded = RecordedIoGroup::from_canonical_bytes(bytes.as_ref(), bounds()).unwrap();
    assert_eq!(decoded.stream_ids().collect::<Vec<_>>(), vec![3, 5]);
    assert_eq!((decoded.streams(), decoded.operations()), (2, 2));
    assert_eq!(decoded.to_canonical_bytes(16_384).unwrap().as_ref(), bytes.as_ref());
    replay(decoded);
}

#[test]
fn every_truncated_prefix_and_single_bit_change_is_refused() {
    let bytes = captured().to_canonical_bytes(16_384).unwrap();
    for length in 0..bytes.as_ref().len() {
        assert!(RecordedIoGroup::from_canonical_bytes(&bytes.as_ref()[..length], bounds()).is_err(), "prefix {length}");
    }
    for index in 0..bytes.as_ref().len() {
        for bit in 0..8 {
            let mut changed = bytes.as_ref().to_vec(); changed[index] ^= 1 << bit;
            assert!(RecordedIoGroup::from_canonical_bytes(&changed, bounds()).is_err(), "byte {index} bit {bit}");
        }
    }
}

#[test]
fn exact_output_bound_and_every_independent_import_bound_are_enforced() {
    let tape = captured(); let bytes = tape.to_canonical_bytes(16_384).unwrap(); let n = bytes.as_ref().len();
    assert_eq!(tape.to_canonical_bytes(n).unwrap().as_ref(), bytes.as_ref());
    assert!(tape.to_canonical_bytes(n - 1).is_err());
    for kind in 0..6 {
        let mut limit = bounds();
        match kind {
            0 => limit.max_encoded_bytes = n - 1,
            1 => limit.max_streams = 1,
            2 => limit.max_events = 1,
            3 => limit.max_group_bytes = 0,
            4 => limit.per_stream.max_encoded_bytes = 0,
            _ => limit.per_stream.max_decoded_bytes = 0,
        }
        assert!(RecordedIoGroup::from_canonical_bytes(bytes.as_ref(), limit).is_err(), "bound {kind}");
    }
    replay(tape);
}

#[test]
fn duplicate_id_unknown_ordinal_bad_counts_and_unknown_tag_are_rejected() {
    let bytes = captured().to_canonical_bytes(16_384).unwrap();
    let (second, order) = positions(bytes.as_ref());
    for kind in 0..4 {
        let mut changed = bytes.as_ref().to_vec();
        match kind {
            0 => changed[second..second + 8].copy_from_slice(&3_u64.to_le_bytes()),
            1 => changed[order..order + 8].copy_from_slice(&2_u64.to_le_bytes()),
            2 => changed[order + ENTRY_BYTES..order + ENTRY_BYTES + 8].copy_from_slice(&0_u64.to_le_bytes()),
            _ => changed[order + 8] = 255,
        }
        resign(&mut changed);
        assert!(RecordedIoGroup::from_canonical_bytes(&changed, bounds()).is_err(), "mutation {kind}");
    }
}

#[test]
// Iterating two byte offsets via an array literal; not a tuple->array conversion.
#[allow(clippy::tuple_array_conversions)]
fn nested_corruption_is_not_hidden_by_a_recomputed_group_checksum() {
    let bytes = captured().to_canonical_bytes(16_384).unwrap(); let (second, order) = positions(bytes.as_ref());
    for end in [second, order] {
        let mut changed = bytes.as_ref().to_vec(); changed[end - 1] ^= 1; resign(&mut changed);
        assert!(matches!(RecordedIoGroup::from_canonical_bytes(&changed, bounds()), Err(IoGroupTapeError::Stream(IoTapeError::Checksum))));
    }
}

#[test]
fn authenticated_structure_cannot_make_component_operation_mismatch_a_success() {
    let bytes = captured().to_canonical_bytes(16_384).unwrap(); let (_, order) = positions(bytes.as_ref());
    let mut changed = bytes.as_ref().to_vec(); changed[order + 8] = 0; resign(&mut changed);
    let replay = RecordedIoGroup::from_canonical_bytes(&changed, bounds()).unwrap().replay();
    let mut a = replay.open(3).unwrap(); let mut storage = [0]; let mut buf = ReadBuf::new(&mut storage);
    assert!(matches!(Pin::new(&mut a).poll_read(&mut Context::from_waker(Waker::noop()), &mut buf), Poll::Ready(Err(_))));
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Diverged(IoGroupReplayError::Coverage(3))));
}

#[test]
fn per_stream_exhaustion_refuses_even_while_other_streams_have_a_tail() {
    let replay = captured().replay(); let mut a = replay.open(3).unwrap(); let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(Pin::new(&mut a).poll_write(&mut cx, b"a"), Poll::Ready(Ok(1))));
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Remaining(1)));
    assert!(matches!(Pin::new(&mut a).poll_write(&mut cx, b"extra"), Poll::Ready(Err(_))));
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Diverged(IoGroupReplayError::Exhausted(3))));
}

#[test]
fn framing_version_and_address_space_overflow_refuse_before_decoding() {
    let bytes = captured().to_canonical_bytes(16_384).unwrap();
    let mut changed = bytes.as_ref().to_vec(); changed.push(0);
    assert!(matches!(RecordedIoGroup::from_canonical_bytes(&changed, bounds()), Err(IoGroupTapeError::TrailingData)));
    let mut changed = bytes.as_ref().to_vec(); changed[8..12].copy_from_slice(&2_u32.to_le_bytes()); resign(&mut changed);
    assert!(matches!(RecordedIoGroup::from_canonical_bytes(&changed, bounds()), Err(IoGroupTapeError::Format)));
    let mut changed = bytes.as_ref().to_vec(); changed[HEADER + 8..HEADER + 16].copy_from_slice(&u64::MAX.to_le_bytes()); resign(&mut changed);
    let mut limit = bounds(); limit.per_stream.max_encoded_bytes = usize::MAX;
    assert!(matches!(RecordedIoGroup::from_canonical_bytes(&changed, limit), Err(IoGroupTapeError::Overflow)));
}

#[test]
fn empty_group_has_portable_known_bytes_and_zero_decoded_storage() {
    let group = IoRecordingGroup::new(IoGroupCaptureLimits { max_streams: 0, max_events: 0, per_stream: IoCaptureLimits::new(0, 0, 0, 0) });
    let bytes = group.finish().unwrap().to_canonical_bytes(60).unwrap();
    let hex: String = bytes.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(hex, "415355504d494f000100000000000000000000000000000000000000606602230361e6766e2290ad0e31b6fd87c6ffd8c91a29fee43a1ede1b48b88b");
    let mut limit = bounds(); limit.max_group_bytes = 0; limit.max_streams = 0; limit.max_events = 0;
    RecordedIoGroup::from_canonical_bytes(bytes.as_ref(), limit).unwrap().replay().verify_complete().unwrap();
    assert!(!format!("{bytes:?}").contains("ASUPMIO"));
}
