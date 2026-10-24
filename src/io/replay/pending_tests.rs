//! Pending-aware windows over real duplex I/O, including dropped consumers.

use super::*;
use crate::io::{AsyncReadExt, duplex};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Wake;

fn limits() -> IoCaptureLimits {
    IoCaptureLimits::new(64, 1024, 1024, 8)
}

fn decode_limits() -> IoTapeDecodeLimits {
    IoTapeDecodeLimits::new(16 * 1024, limits(), 32 * 1024)
}

fn roundtrip(tape: &IoTape) -> IoTape {
    let bytes = tape.to_canonical_bytes(16 * 1024).unwrap();
    let replayed = IoTape::from_canonical_bytes(bytes.as_ref(), decode_limits()).unwrap();
    assert_eq!(
        replayed.to_canonical_bytes(16 * 1024).unwrap().as_ref(),
        bytes.as_ref()
    );
    replayed
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn count_waker() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    (count, waker)
}

fn write_ready(io: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) {
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(io).poll_write(&mut cx, bytes),
        Poll::Ready(Ok(count)) if count == bytes.len()
    ));
}

fn read_ready(io: &mut (impl AsyncRead + Unpin), expected: &[u8]) {
    let mut bytes = vec![0_u8; expected.len()];
    let mut buf = ReadBuf::new(&mut bytes);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(Pin::new(io).poll_read(&mut cx, &mut buf), Poll::Ready(Ok(()))));
    assert_eq!(buf.filled(), expected);
}

#[test]
fn a_dropped_pending_read_is_a_complete_window_without_io_completion() {
    let (stream, mut peer) = duplex(8);
    let mut recording = RecordingIo::new_with_pending_io(stream, limits());
    write_ready(&mut recording, b"request");
    let mut input = [0xA5_u8; 4];
    let mut cx = Context::from_waker(Waker::noop());
    let mut pending = Box::pin(recording.read(&mut input));
    assert!(pending.as_mut().poll(&mut cx).is_pending());
    drop(pending);
    assert_eq!(input, [0xA5; 4], "a pending read supplied no invented bytes");
    let (live_stream, tape) = recording.into_parts();
    let tape = tape.unwrap();
    assert!(tape.records_pending_polls());
    assert_eq!((tape.operations(), tape.read_bytes(), tape.write_bytes()), (2, 0, 7));
    read_ready(&mut peer, b"request");

    let encoded = tape.to_canonical_bytes(16 * 1024).unwrap();
    assert_eq!(&encoded.as_ref()[8..12], &2_u32.to_le_bytes());
    let mut replay = roundtrip(&tape).replay();
    write_ready(&mut replay, b"request");
    let (wakes, waker) = count_waker();
    let mut cx = Context::from_waker(&waker);
    let mut replayed = [0x5A_u8; 4];
    let mut pending = Box::pin(replay.read(&mut replayed));
    assert!(pending.as_mut().poll(&mut cx).is_pending());
    drop(pending);
    assert_eq!(replayed, [0x5A; 4]);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0, "the captured tail must stay parked");
    assert_eq!(replay.consumed_operations(), 2);
    assert!(replay.verify_complete().is_ok(), "window consumed; read never completed");

    // A newly constructed operation is not an unlimited replay of that tail,
    // even with identical capacity and the same buffer.
    let mut another = Box::pin(replay.read(&mut replayed));
    assert!(matches!(another.as_mut().poll(&mut cx), Poll::Ready(Err(_))));
    drop(another);
    assert_eq!(replay.failure().unwrap().reason, IoReplayMismatch::Exhausted);
    assert!(matches!(replay.verify_complete(), Err(IoReplayCompletionError::Diverged(_))));
    drop(live_stream);
}

#[test]
fn other_direction_progress_never_rewakes_an_exhausted_pending_tail() {
    let (stream, _peer) = duplex(4);
    let mut recording = RecordingIo::new_with_pending_io(stream, limits());
    let mut bytes = [0_u8; 2];
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut recording)
        .poll_read(&mut cx, &mut ReadBuf::new(&mut bytes))
        .is_pending());
    write_ready(&mut recording, b"x");
    let (_stream, tape) = recording.into_parts();
    let mut replay = roundtrip(&tape.unwrap()).replay();
    let (read_wakes, read_waker) = count_waker();
    let (write_wakes, write_waker) = count_waker();
    let mut read_cx = Context::from_waker(&read_waker);
    let mut write_cx = Context::from_waker(&write_waker);

    // An early opposite-direction call waits for the recorded read observation.
    assert!(Pin::new(&mut replay).poll_write(&mut write_cx, b"x").is_pending());
    assert_eq!(replay.consumed_operations(), 0);
    assert!(Pin::new(&mut replay)
        .poll_read(&mut read_cx, &mut ReadBuf::new(&mut bytes))
        .is_pending());
    assert_eq!(write_wakes.0.load(Ordering::SeqCst), 1);
    assert_eq!(read_wakes.0.load(Ordering::SeqCst), 0);
    assert!(matches!(Pin::new(&mut replay).poll_write(&mut write_cx, b"x"), Poll::Ready(Ok(1))));
    assert_eq!(read_wakes.0.load(Ordering::SeqCst), 0);
    assert!(replay.verify_complete().is_ok());
}

#[test]
fn a_backpressured_write_has_one_pending_observation_and_one_ready_retry() {
    let (stream, mut peer) = duplex(1);
    let mut recording = RecordingIo::new_with_pending_io(stream, limits());
    write_ready(&mut recording, b"a");
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut recording).poll_write(&mut cx, b"b").is_pending());
    read_ready(&mut peer, b"a");
    write_ready(&mut recording, b"b");
    let (_stream, tape) = recording.into_parts();
    let tape = tape.unwrap();
    assert_eq!((tape.operations(), tape.write_bytes()), (3, 3));
    let mut replay = roundtrip(&tape).replay();
    write_ready(&mut replay, b"a");
    let (wakes, waker) = count_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut replay).poll_write(&mut cx, b"b").is_pending());
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1, "a recorded retry can progress");
    assert!(matches!(Pin::new(&mut replay).poll_write(&mut cx, b"b"), Poll::Ready(Ok(1))));
    assert!(replay.verify_complete().is_ok());
    assert!(matches!(Pin::new(&mut replay).poll_write(&mut cx, b"b"), Poll::Ready(Err(_))));
    assert_eq!(replay.failure().unwrap().reason, IoReplayMismatch::Exhausted);
}

#[test]
fn pending_request_identity_includes_capacity_bytes_and_vector_boundaries() {
    let (stream, _peer) = duplex(1);
    let mut recording = RecordingIo::new_with_pending_io(stream, limits());
    let mut storage = [0_u8; 5];
    let mut buf = ReadBuf::new(&mut storage);
    buf.put_slice(b"a");
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut recording).poll_read(&mut cx, &mut buf).is_pending());
    let (_stream, tape) = recording.into_parts();
    let tape = tape.unwrap();

    let mut replay = roundtrip(&tape).replay();
    let mut replacement = [0_u8; 5];
    let mut buf = ReadBuf::new(&mut replacement);
    buf.put_slice(b"z");
    assert!(Pin::new(&mut replay).poll_read(&mut cx, &mut buf).is_pending());
    assert_eq!(buf.filled(), b"z", "buffer addresses and prior bytes are caller-owned");
    assert!(replay.verify_complete().is_ok());
    let mut changed = roundtrip(&tape).replay();
    assert!(matches!(
        Pin::new(&mut changed).poll_read(&mut cx, &mut ReadBuf::new(&mut [0_u8; 5])),
        Poll::Ready(Err(_))
    ));
    assert_eq!(changed.failure().unwrap().reason, IoReplayMismatch::Request);

    let (mut stream, _peer) = duplex(1);
    write_ready(&mut stream, b"a");
    let mut recording = RecordingIo::new_with_pending_io(stream, limits());
    let requested = [IoSlice::new(b"c"), IoSlice::new(b"de")];
    assert!(Pin::new(&mut recording).poll_write_vectored(&mut cx, &requested).is_pending());
    let (_stream, tape) = recording.into_parts();
    let tape = tape.unwrap();
    assert_eq!((tape.operations(), tape.write_bytes()), (1, 3));
    let mut replay = roundtrip(&tape).replay();
    assert!(Pin::new(&mut replay).poll_write_vectored(&mut cx, &requested).is_pending());
    assert!(replay.verify_complete().is_ok());
    for changed in [
        [IoSlice::new(b"c"), IoSlice::new(b"df")],
        [IoSlice::new(b"cd"), IoSlice::new(b"e")],
    ] {
        let mut replay = roundtrip(&tape).replay();
        assert!(matches!(
            Pin::new(&mut replay).poll_write_vectored(&mut cx, &changed),
            Poll::Ready(Err(_))
        ));
        assert_eq!(replay.failure().unwrap().reason, IoReplayMismatch::Request);
        assert_eq!(replay.consumed_operations(), 0);
    }
    let mut replay = roundtrip(&tape).replay();
    assert!(matches!(Pin::new(&mut replay).poll_write(&mut cx, b"cde"), Poll::Ready(Err(_))));
    assert_eq!(replay.failure().unwrap().reason, IoReplayMismatch::Operation);
}

#[test]
fn pending_capture_bounds_preserve_live_results_and_provider_ownership() {
    for (bounded, expected) in [
        (IoCaptureLimits::new(1, 0, 8, 2), IoCaptureError::Limit("operations")),
        (IoCaptureLimits::new(8, 0, 1, 2), IoCaptureError::Limit("write bytes")),
    ] {
        let (mut stream, mut peer) = duplex(1);
        write_ready(&mut stream, b"a");
        let mut recording = RecordingIo::new_with_pending_io(stream, bounded);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut recording).poll_write(&mut cx, b"b").is_pending());
        assert!(Pin::new(&mut recording).poll_write(&mut cx, b"c").is_pending());
        assert_eq!(recording.capture_error(), Some(expected));
        read_ready(&mut peer, b"a");
        write_ready(&mut recording, b"c");
        read_ready(&mut peer, b"c");
        let (mut stream, refused) = recording.into_parts();
        assert_eq!(refused.unwrap_err(), expected);
        write_ready(&mut stream, b"d");
        read_ready(&mut peer, b"d");
    }
}

fn all_pending_tape() -> IoTape {
    IoTape {
        events: vec![
            Event::Pending(PendingRequest::Read { capacity: 4 }),
            Event::Pending(PendingRequest::Write {
                length: 2,
                slices: None,
                digest: WriteInput::Scalar(b"xy").digest(),
            }),
            Event::Pending(PendingRequest::Write {
                length: 2,
                slices: Some(vec![1, 1]),
                digest: WriteInput::Scalar(b"xy").digest(),
            }),
            Event::Pending(PendingRequest::Flush),
            Event::Pending(PendingRequest::Shutdown),
        ],
        read_bytes: 0,
        write_bytes: 4,
        vectored: true,
        pending_polls: true,
    }
}

fn reseal(bytes: &mut [u8], version: u32) {
    let body = bytes.len() - 32;
    let mut digest = Sha256::new();
    digest.update(if version == 1 {
        b"asupersync.io-tape.v1"
    } else {
        b"asupersync.io-tape.v2"
    });
    digest.update(&bytes[..body]);
    bytes[body..].copy_from_slice(&digest.finalize());
}

#[test]
fn pending_v2_persistence_is_bounded_and_rejects_malformed_request_metadata() {
    let tape = all_pending_tape();
    let encoded = tape.to_canonical_bytes(16 * 1024).unwrap();
    let mut replay = roundtrip(&tape).replay();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut replay)
        .poll_read(&mut cx, &mut ReadBuf::new(&mut [0_u8; 4]))
        .is_pending());
    assert!(Pin::new(&mut replay).poll_write(&mut cx, b"xy").is_pending());
    assert!(Pin::new(&mut replay)
        .poll_write_vectored(&mut cx, &[IoSlice::new(b"x"), IoSlice::new(b"y")])
        .is_pending());
    assert!(Pin::new(&mut replay).poll_flush(&mut cx).is_pending());
    assert!(Pin::new(&mut replay).poll_shutdown(&mut cx).is_pending());
    assert_eq!(replay.consumed_operations(), 5);
    assert!(replay.verify_complete().is_ok(), "no I/O operation was completed");

    for end in 0..encoded.as_ref().len() {
        assert!(IoTape::from_canonical_bytes(&encoded.as_ref()[..end], decode_limits()).is_err());
    }
    let start = 46 + std::env::consts::OS.len();
    let mut malformed = encoded.as_ref().to_vec();
    malformed[start] = 255;
    reseal(&mut malformed, 2);
    assert!(matches!(IoTape::from_canonical_bytes(&malformed, decode_limits()),
        Err(IoTapeError::Invalid("event tag"))));
    let mut malformed = encoded.as_ref().to_vec();
    let vector = start + 9 + 41;
    malformed[vector + 1..vector + 9].copy_from_slice(&1_u64.to_le_bytes());
    reseal(&mut malformed, 2);
    assert!(matches!(IoTape::from_canonical_bytes(&malformed, decode_limits()),
        Err(IoTapeError::Invalid("vector sum"))));

    let mut old_version = encoded.as_ref().to_vec();
    old_version[8..12].copy_from_slice(&1_u32.to_le_bytes());
    reseal(&mut old_version, 1);
    assert!(matches!(IoTape::from_canonical_bytes(&old_version, decode_limits()),
        Err(IoTapeError::Invalid("event tag"))));
    for (bounded, expected) in [
        (IoTapeDecodeLimits::new(16 * 1024, IoCaptureLimits::new(4, 1024, 1024, 8), 32 * 1024),
            IoTapeError::Limit("operations")),
        (IoTapeDecodeLimits::new(16 * 1024, IoCaptureLimits::new(64, 1024, 3, 8), 32 * 1024),
            IoTapeError::Limit("write bytes")),
        (IoTapeDecodeLimits::new(16 * 1024, IoCaptureLimits::new(64, 1024, 1024, 1), 32 * 1024),
            IoTapeError::Limit("vectored slices")),
        (IoTapeDecodeLimits::new(16 * 1024, limits(), 1), IoTapeError::Limit("decoded bytes")),
    ] {
        assert_eq!(IoTape::from_canonical_bytes(encoded.as_ref(), bounded).unwrap_err(), expected);
    }
}

#[test]
fn completed_only_capture_keeps_v1_bytes_and_pending_exhaustion() {
    let (stream, _peer) = duplex(1);
    let mut recording = RecordingIo::new(stream, limits());
    let vectored = recording.is_write_vectored();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(Pin::new(&mut recording).poll_flush(&mut cx), Poll::Ready(Ok(()))));
    assert!(Pin::new(&mut recording)
        .poll_read(&mut cx, &mut ReadBuf::new(&mut [0_u8; 1]))
        .is_pending());
    let (_stream, tape) = recording.into_parts();
    let tape = tape.unwrap();
    assert!(!tape.records_pending_polls());
    assert_eq!(tape.operations(), 1);
    let encoded = tape.to_canonical_bytes(1024).unwrap();
    let os = std::env::consts::OS.as_bytes();
    let mut expected = b"ASUPIO\0\0".to_vec();
    expected.extend_from_slice(&1_u32.to_le_bytes());
    expected.push(u8::from(vectored));
    for field in [1_u64, 0, 0, 0] {
        expected.extend_from_slice(&field.to_le_bytes());
    }
    expected.push(u8::try_from(os.len()).unwrap());
    expected.extend_from_slice(os);
    expected.extend_from_slice(&[3, 0]);
    expected.extend_from_slice(&[0_u8; 32]);
    reseal(&mut expected, 1);
    assert_eq!(encoded.as_ref(), expected.as_slice());
    let mut replay = roundtrip(&tape).replay();
    assert!(matches!(Pin::new(&mut replay).poll_flush(&mut cx), Poll::Ready(Ok(()))));
    assert!(matches!(Pin::new(&mut replay)
        .poll_read(&mut cx, &mut ReadBuf::new(&mut [0_u8; 1])),
        Poll::Ready(Err(_))));
    assert_eq!(replay.failure().unwrap().reason, IoReplayMismatch::Exhausted);
}
