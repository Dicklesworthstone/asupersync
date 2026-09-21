use super::*;
use crate::io::{AsyncWrite, replay::IoCaptureLimits};
use crate::io::replay::IoTapeDecodeLimits;
use crate::io::replay_group::{IoGroupCaptureLimits, IoRecordingGroup};
use std::{io, pin::Pin, task::{Context, Poll, Waker}};

struct Sink;
impl AsyncWrite for Sink {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> { Poll::Ready(Ok(buf.len())) }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}
fn captured() -> RecordedIoGroup {
    let group = IoRecordingGroup::new(IoGroupCaptureLimits { max_streams: 2, max_events: 4, per_stream: IoCaptureLimits::new(4, 0, 8, 0) });
    for (id, bytes) in [(3, b"a"), (5, b"b")] {
        let mut stream = group.register(id, Sink).unwrap();
        assert!(matches!(Pin::new(&mut stream).poll_write(&mut Context::from_waker(Waker::noop()), bytes), Poll::Ready(Ok(1))));
        stream.into_inner();
    }
    group.finish().unwrap()
}
fn binding() -> ReplayArchiveBinding { ReplayArchiveBinding { source: [7; 32], capture: [9; 32] } }
fn bounds() -> IoGroupDecodeLimits {
    IoGroupDecodeLimits { max_encoded_bytes: 8192, max_streams: 2, max_events: 4, max_group_bytes: 4096,
        per_stream: IoTapeDecodeLimits::new(4096, IoCaptureLimits::new(4, 0, 8, 0), 2048) }
}

#[test]
fn encrypted_group_replays_only_after_all_streams_and_order_validate() {
    let mut sealer = ReplayArchiveKey::new([31; 32]).into_sealer([1; 16]); // public test key only
    let key = ReplayArchiveKey::new([31; 32]);
    let group = captured(); let canonical = group.to_canonical_bytes(8192).unwrap();
    let archive = sealer.seal_io_group(&group, binding(), 16_384).unwrap(); drop(group);
    let restored = key.open_io_group(archive.as_ref(), binding(), 16_384, bounds()).unwrap();
    assert_eq!(restored.to_canonical_bytes(8192).unwrap().as_ref(), canonical.as_ref());
    let replay = restored.replay(); let mut a = replay.open(3).unwrap(); let mut b = replay.open(5).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut b).poll_write(&mut cx, b"b").is_pending());
    assert!(matches!(Pin::new(&mut a).poll_write(&mut cx, b"a"), Poll::Ready(Ok(1))));
    assert!(matches!(Pin::new(&mut b).poll_write(&mut cx, b"b"), Poll::Ready(Ok(1))));
    replay.verify_complete().unwrap();
}

#[test]
fn ciphertext_identity_key_and_profile_substitution_all_refuse() {
    let mut sealer = ReplayArchiveKey::new([31; 32]).into_sealer([2; 16]);
    let key = ReplayArchiveKey::new([31; 32]);
    let archive = sealer.seal_io_group(&captured(), binding(), 16_384).unwrap();
    let mut changed_binding = binding(); changed_binding.capture[0] ^= 1;
    assert_eq!(key.open_io_group(archive.as_ref(), changed_binding, 16_384, bounds()).unwrap_err(), IoGroupArchiveError::Archive(ReplayArchiveError::Authentication));
    assert_eq!(ReplayArchiveKey::new([32; 32]).open_io_group(archive.as_ref(), binding(), 16_384, bounds()).unwrap_err(), IoGroupArchiveError::Archive(ReplayArchiveError::Authentication));
    for index in [12, 24, 48, super::super::HEADER, archive.as_ref().len() - 1] {
        let mut changed = archive.as_ref().to_vec(); changed[index] ^= 1;
        assert!(key.open_io_group(&changed, binding(), 16_384, bounds()).is_err());
    }
    // A valid AEAD under another profile is still not a multi-stream archive.
    let plaintext = captured().to_canonical_bytes(8192).unwrap();
    let wrong = sealer.seal_payload(plaintext.as_ref(), binding(), super::super::SESSION, 16_384).unwrap();
    assert_eq!(key.open_io_group(wrong.as_ref(), binding(), 16_384, bounds()).unwrap_err(), IoGroupArchiveError::Archive(ReplayArchiveError::Format));
}

#[test]
fn authentication_precedes_nested_decoder_and_all_bounds_still_apply() {
    let mut sealer = ReplayArchiveKey::new([31; 32]).into_sealer([3; 16]);
    let key = ReplayArchiveKey::new([31; 32]);
    let archive = sealer.seal_io_group(&captured(), binding(), 16_384).unwrap();
    let mut bound = bounds(); bound.max_streams = 0;
    assert_eq!(key.open_io_group(archive.as_ref(), binding(), 16_384, bound).unwrap_err(), IoGroupArchiveError::Tape(IoGroupTapeError::Limit("streams")));
    let mut changed = archive.as_ref().to_vec(); changed[super::super::HEADER] ^= 1;
    assert_eq!(key.open_io_group(&changed, binding(), 16_384, bound).unwrap_err(), IoGroupArchiveError::Archive(ReplayArchiveError::Authentication));
    assert_eq!(key.open_io_group(archive.as_ref(), binding(), 0, bounds()).unwrap_err(), IoGroupArchiveError::Archive(ReplayArchiveError::EncodedLimit));
    let mut bound = bounds(); bound.max_encoded_bytes = 0;
    assert_eq!(key.open_io_group(archive.as_ref(), binding(), 16_384, bound).unwrap_err(), IoGroupArchiveError::Archive(ReplayArchiveError::PlaintextLimit));
}

#[test]
fn group_profile_shares_the_existing_nonce_sequence_and_exhaustion_guard() {
    let mut sealer = ReplayArchiveKey::new([31; 32]).into_sealer([4; 16]);
    let group = captured();
    let first = sealer.seal_io_group(&group, binding(), 16_384).unwrap();
    let other = sealer.seal_payload(b"fixture", binding(), super::super::ORDERED, 1024).unwrap();
    let third = sealer.seal_io_group(&group, binding(), 16_384).unwrap();
    for (number, archive) in [first, other, third].iter().enumerate() {
        assert_eq!(u64::from_le_bytes(archive.as_ref()[40..48].try_into().unwrap()), number as u64);
    }
    sealer.next = Some(u64::MAX);
    sealer.seal_io_group(&group, binding(), 16_384).unwrap();
    assert_eq!(sealer.seal_io_group(&group, binding(), 16_384).unwrap_err(), IoGroupArchiveError::Archive(ReplayArchiveError::NonceExhausted));
}

#[test]
fn empty_group_matches_an_independent_libsodium_profile_three_vector() {
    let group = IoRecordingGroup::new(IoGroupCaptureLimits { max_streams: 0, max_events: 0, per_stream: IoCaptureLimits::new(0, 0, 0, 0) }).finish().unwrap();
    let mut sealer = ReplayArchiveKey::new([31; 32]).into_sealer([5; 16]);
    let encrypted = sealer.seal_io_group(&group, binding(), 188).unwrap();
    let hex: String = encrypted.as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(hex, "41535550454e430001000000030000003c000000000000000505050505050505050505050505050500000000000000000707070707070707070707070707070707070707070707070707070707070707090909090909090909090909090909090909090909090909090909090909090944597cc57c830327bd83b826d672ba67b5dc512e4453e6599201d97db3b36ebf679ac2d763f63a10c15b0ce534ac287f27d8a0299ddc122b97cc186377bd3f89cfb3a3cf3b5fff4a33f8942f");
}
