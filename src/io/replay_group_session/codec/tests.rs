use super::*;
use crate::io::replay::IoCaptureLimits;
use crate::io::replay_group_session::{GroupSessionCaptureLimits, RecordingGroupSession};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::time::{TimeSource, VirtualClock};
use crate::types::TaskId;
use crate::util::DetEntropy;
use crate::util::entropy::EntropySource;
use crate::util::entropy_replay::EntropyCaptureLimits;
use std::{io, pin::Pin, sync::Arc, task::{Context, Poll, Waker}};

struct Input(&'static [u8]);
impl AsyncRead for Input {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut(); let n = this.0.len().min(buf.remaining());
        buf.put_slice(&this.0[..n]); this.0 = &this.0[n..]; Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Input {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> { Poll::Ready(Ok(buf.len())) }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}
fn read(io: &mut (impl AsyncRead + Unpin)) -> Poll<io::Result<Vec<u8>>> {
    let mut bytes = [0; 6]; let mut buf = ReadBuf::new(&mut bytes);
    Pin::new(io).poll_read(&mut Context::from_waker(Waker::noop()), &mut buf)
        .map(|result| result.map(|()| buf.filled().to_vec()))
}
fn capture() -> RecordedGroupSession {
    let session = RecordingGroupSession::new(Arc::new(DetEntropy::new(31)), Arc::new(VirtualClock::new()), GroupSessionCaptureLimits {
        max_streams: 3, max_effects: 64, per_stream: IoCaptureLimits::new(32, 4096, 4096, 8),
        entropy: EntropyCaptureLimits::new(32, 4096, 8), clock_observations: 32,
    }).unwrap();
    let mut a = session.register(u64::MAX, Input(b"secret")).unwrap();
    let mut b = session.register(0, Input(b"reply!")).unwrap();
    assert!(matches!(read(&mut a), Poll::Ready(Ok(_))));
    session.clock().now();
    let child = session.entropy().fork(TaskId::new_for_test(7, 3));
    child.next_u64();
    assert!(matches!(read(&mut b), Poll::Ready(Ok(_))));
    a.into_inner(); b.into_inner(); session.finish().unwrap()
}
fn limits() -> GroupSessionDecodeLimits {
    GroupSessionDecodeLimits {
        max_encoded_bytes: 65_536, max_streams: 8, max_effects: 256, max_group_bytes: 65_536,
        per_stream: IoTapeDecodeLimits::new(16_384, IoCaptureLimits::new(256, 4096, 4096, 16), 32_768),
        entropy: EntropyTapeDecodeLimits::new(16_384, EntropyCaptureLimits::new(256, 4096, 16), 16_384),
        clock: TimeTapeDecodeLimits::new(16_384, 256, 4096),
    }
}
fn resign(bytes: &mut [u8]) {
    let end = bytes.len() - CHECKSUM;
    let digest = checksum(&bytes[..end]); bytes[end..].copy_from_slice(&digest);
}
fn order_start(bytes: &[u8]) -> usize { bytes.len() - CHECKSUM - count(bytes, 20).unwrap() * EFFECT_BYTES }
fn replay(tape: RecordedGroupSession) {
    let replay = tape.replay();
    let mut b = replay.open(0).unwrap(); let mut a = replay.open(u64::MAX).unwrap();
    assert!(read(&mut b).is_pending());
    assert!(matches!(read(&mut a), Poll::Ready(Ok(bytes)) if bytes == b"secret"));
    replay.clock().try_now().unwrap();
    replay.entropy().try_fork(TaskId::new_for_test(7, 3)).unwrap().try_next_u64().unwrap();
    assert!(matches!(read(&mut b), Poll::Ready(Ok(bytes)) if bytes == b"reply!"));
    drop(a); drop(b); replay.verify_complete().unwrap();
}

#[test]
fn canonical_roundtrip_preserves_every_provider_and_cross_stream_order() {
    let tape = capture(); let encoded = tape.to_canonical_bytes(65_536).unwrap(); drop(tape);
    let restored = RecordedGroupSession::from_canonical_bytes(encoded.as_ref(), limits()).unwrap();
    assert_eq!(restored.to_canonical_bytes(65_536).unwrap().as_ref(), encoded.as_ref());
    assert_eq!(restored.stream_ids().collect::<Vec<_>>(), [u64::MAX, 0]);
    replay(restored);
}

#[test]
fn every_truncated_prefix_and_changed_byte_is_refused() {
    let encoded = capture().to_canonical_bytes(65_536).unwrap(); let bytes = encoded.as_ref();
    for end in 0..bytes.len() {
        assert!(RecordedGroupSession::from_canonical_bytes(&bytes[..end], limits()).is_err(), "prefix {end}");
    }
    for index in 0..bytes.len() {
        let mut changed = bytes.to_vec(); changed[index] ^= 1;
        assert!(RecordedGroupSession::from_canonical_bytes(&changed, limits()).is_err(), "byte {index}");
    }
}

#[test]
fn exact_encoder_bound_succeeds_and_short_bound_preserves_capture() {
    let tape = capture(); let encoded = tape.to_canonical_bytes(65_536).unwrap(); let size = encoded.as_ref().len();
    assert!(tape.to_canonical_bytes(size - 1).is_err());
    assert_eq!(tape.to_canonical_bytes(size).unwrap().as_ref(), encoded.as_ref());
    replay(tape);
}

#[test]
fn independent_outer_nested_and_allocation_bounds_are_enforced() {
    let encoded = capture().to_canonical_bytes(65_536).unwrap();
    for which in 0..10 {
        let mut bound = limits();
        match which {
            0 => bound.max_encoded_bytes = encoded.as_ref().len() - 1,
            1 => bound.max_streams = 1,
            2 => bound.max_effects = 4,
            3 => bound.max_group_bytes = 0,
            4 => bound.per_stream.max_encoded_bytes = 0,
            5 => bound.entropy.max_encoded_bytes = 0,
            6 => bound.clock.max_encoded_bytes = 0,
            7 => bound.per_stream.max_decoded_bytes = 0,
            8 => bound.entropy.max_decoded_bytes = 0,
            _ => bound.clock.max_decoded_bytes = 0,
        }
        assert!(RecordedGroupSession::from_canonical_bytes(encoded.as_ref(), bound).is_err(), "bound {which}");
    }
}

#[test]
fn forged_lengths_counts_and_trailing_bytes_refuse_before_large_allocation() {
    let encoded = capture().to_canonical_bytes(65_536).unwrap();
    for offset in [12, 20, 28, 36, HEADER + 8] {
        let mut changed = encoded.as_ref().to_vec(); changed[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes()); resign(&mut changed);
        assert!(RecordedGroupSession::from_canonical_bytes(&changed, limits()).is_err(), "offset {offset}");
    }
    let mut extra = encoded.as_ref().to_vec(); extra.push(0);
    assert!(matches!(RecordedGroupSession::from_canonical_bytes(&extra, limits()), Err(GroupSessionTapeError::TrailingData)));
}

#[test]
fn resigning_duplicate_stream_ids_and_invalid_ordinals_cannot_bypass_coverage() {
    let encoded = capture().to_canonical_bytes(65_536).unwrap();
    let mut duplicate = encoded.as_ref().to_vec();
    let second = HEADER + 16 + count(&duplicate, HEADER + 8).unwrap();
    duplicate[second..second + 8].copy_from_slice(&u64::MAX.to_le_bytes()); resign(&mut duplicate);
    assert!(matches!(RecordedGroupSession::from_canonical_bytes(&duplicate, limits()), Err(GroupSessionTapeError::Coverage)));
    let mut ordinal = encoded.as_ref().to_vec(); let order = order_start(&ordinal);
    ordinal[order + 1..order + 9].copy_from_slice(&2u64.to_le_bytes()); resign(&mut ordinal);
    assert!(matches!(RecordedGroupSession::from_canonical_bytes(&ordinal, limits()), Err(GroupSessionTapeError::Coverage)));
}

#[test]
fn forged_fork_topology_unused_fields_and_categories_are_not_canonical() {
    let encoded = capture().to_canonical_bytes(65_536).unwrap();
    for which in 0..5 {
        let mut changed = encoded.as_ref().to_vec(); let order = order_start(&changed);
        match which {
            0 => changed[order + 2 * EFFECT_BYTES + 9] = 2, // first child must be ordinal one
            1 => changed[order + 3 * EFFECT_BYTES + 1] = 2, // nonexistent entropy source
            2 => changed[order + EFFECT_BYTES + 1] = 1, // clock has zero subject
            3 => changed[order + 9] = 1, // I/O has zero child
            _ => changed[order] = 255,
        }
        resign(&mut changed);
        assert!(RecordedGroupSession::from_canonical_bytes(&changed, limits()).is_err(), "shape {which}");
    }
}

#[test]
fn nested_corruption_and_coverage_mismatch_fail_even_with_a_valid_outer_checksum() {
    let encoded = capture().to_canonical_bytes(65_536).unwrap();
    let mut nested = encoded.as_ref().to_vec(); nested[HEADER + 16] ^= 1; resign(&mut nested);
    assert!(matches!(RecordedGroupSession::from_canonical_bytes(&nested, limits()), Err(GroupSessionTapeError::Io(_))));
    let mut count_mismatch = encoded.as_ref().to_vec(); let order = order_start(&count_mismatch);
    count_mismatch[order + 4 * EFFECT_BYTES + 1] = 0; resign(&mut count_mismatch);
    assert!(matches!(RecordedGroupSession::from_canonical_bytes(&count_mismatch, limits()), Err(GroupSessionTapeError::Coverage)));
}

#[test]
fn changed_io_kind_is_rejected_by_actual_replay_not_mistaken_for_successful_import() {
    let encoded = capture().to_canonical_bytes(65_536).unwrap();
    let mut changed = encoded.as_ref().to_vec(); let order = order_start(&changed);
    changed[order] = 3; resign(&mut changed); // counts still cover, but first read was not a flush
    let tape = RecordedGroupSession::from_canonical_bytes(&changed, limits()).unwrap();
    let replay = tape.replay(); let mut a = replay.open(u64::MAX).unwrap();
    assert!(matches!(Pin::new(&mut a).poll_flush(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(_))));
    assert!(replay.verify_complete().is_err());
}

#[test]
fn empty_session_roundtrips_with_zero_effects_and_plaintext_debug_is_redacted() {
    let session = RecordingGroupSession::new(Arc::new(DetEntropy::new(0)), Arc::new(VirtualClock::new()), GroupSessionCaptureLimits {
        max_streams: 0, max_effects: 0, per_stream: IoCaptureLimits::new(0, 0, 0, 0),
        entropy: EntropyCaptureLimits::new(0, 0, 1), clock_observations: 0,
    }).unwrap();
    let encoded = session.finish().unwrap().to_canonical_bytes(1024).unwrap();
    RecordedGroupSession::from_canonical_bytes(encoded.as_ref(), limits()).unwrap().replay().verify_complete().unwrap();
    let secret = capture().to_canonical_bytes(65_536).unwrap();
    assert!(secret.as_ref().windows(6).any(|bytes| bytes == b"secret"), "plaintext fixture must really contain payload");
    assert!(!format!("{secret:?}").contains("secret"));
}
