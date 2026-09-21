use super::*;
use crate::io::replay::{IoCaptureLimits, IoTapeDecodeLimits};
use crate::io::replay_session::{RecordingSession, SessionCaptureLimits};
use crate::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::time::replay::TimeTapeDecodeLimits;
use crate::time::{TimeSource, VirtualClock};
use crate::types::Time;
use crate::util::DetEntropy;
use crate::util::entropy::EntropySource;
use crate::util::entropy_replay::{EntropyCaptureLimits, EntropyTapeDecodeLimits};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

const KEY: [u8; 32] = [0x43; 32]; // Fixture only; never a real archive key.
const BINDING: ReplayArchiveBinding = ReplayArchiveBinding { source: [0x11; 32], capture: [0x22; 32] };

#[derive(Default)]
struct Peer { offset: usize, written: Vec<u8> }
impl AsyncRead for Peer {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let response = b"pong";
        let n = (response.len() - this.offset).min(buf.remaining());
        buf.put_slice(&response[this.offset..this.offset + n]);
        this.offset += n;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Peer {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().written.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}

async fn exchange<T: AsyncRead + AsyncWrite + Unpin>(
    io: &mut T, entropy: &dyn EntropySource, clock: &dyn TimeSource,
) -> (u64, Time, [u8; 4]) {
    let nonce = entropy.next_u64();
    let time = clock.now();
    io.write_all(b"secret-request").await.unwrap();
    io.flush().await.unwrap();
    let mut response = [0; 4];
    io.read_exact(&mut response).await.unwrap();
    (nonce, time, response)
}

fn capture_limits() -> SessionCaptureLimits {
    SessionCaptureLimits {
        io: IoCaptureLimits::new(32, 256, 256, 8),
        entropy: EntropyCaptureLimits::new(32, 256, 8),
        clock_observations: 32,
    }
}
fn limits() -> SessionDecodeLimits {
    let capture = capture_limits();
    SessionDecodeLimits {
        max_encoded_bytes: 65_536,
        io: IoTapeDecodeLimits::new(32_768, capture.io, 32_768),
        entropy: EntropyTapeDecodeLimits::new(16_384, capture.entropy, 16_384),
        clock: TimeTapeDecodeLimits::new(16_384, 32, 4096),
    }
}
fn captured() -> (RecordedSession, (u64, Time, [u8; 4])) {
    let mut recording = RecordingSession::new(
        Peer::default(), Arc::new(DetEntropy::new(5)), Arc::new(VirtualClock::new()), capture_limits(),
    ).unwrap();
    let entropy = recording.entropy();
    let clock = recording.clock();
    let output = futures_lite::future::block_on(exchange(recording.io(), entropy.as_ref(), clock.as_ref()));
    let (peer, tape) = recording.into_parts();
    assert_eq!(peer.written, b"secret-request");
    (tape.unwrap(), output)
}
fn sealer() -> ReplayArchiveSealer { ReplayArchiveKey::new(KEY).into_sealer([7; 16]) }

#[test]
fn authenticated_session_roundtrip_runs_the_original_consumer_offline() {
    let (session, expected) = captured();
    let bytes = sealer().seal_session(&session, BINDING, 65_536).unwrap();
    let original = session.to_canonical_bytes(65_536).unwrap();
    assert!(!bytes.as_ref().windows(4).any(|slice| slice == b"pong"));
    drop(session);
    let restored = ReplayArchiveKey::new(KEY).open_session(bytes.as_ref(), BINDING, 65_536, limits()).unwrap();
    assert_eq!(restored.to_canonical_bytes(65_536).unwrap().as_ref(), original.as_ref());
    drop(bytes);
    let output = futures_lite::future::block_on(restored.replay().run(32, |p| {
        Box::pin(exchange(p.io, p.entropy, p.clock))
    })).unwrap();
    assert_eq!(output, expected);
}

#[test]
fn independent_libsodium_vector_pins_header_nonce_ciphertext_and_tag() {
    let key = std::array::from_fn(|index| u8::try_from(index).unwrap());
    let prefix = std::array::from_fn(|index| u8::try_from(index).unwrap());
    let bytes = ReplayArchiveKey::new(key).into_sealer(prefix)
        .seal_payload(b"recorded plaintext\0\xff", BINDING, SESSION, 1024).unwrap();
    // Independently generated with libsodium's XChaCha20-Poly1305 implementation,
    // not this Rust adapter. This pins the full V1 encoding, not a self-roundtrip.
    let expected = "41535550454e430001000000010000001400000000000000000102030405060708090a0b0c0d0e0f0000000000000000111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222221a4d46e53265a8a7cb514c6cff45e930dd53ae457c32fcec11e67b427f7ebea1540b7a48";
    assert_eq!(hex::encode(bytes.as_ref()), expected);
    let plaintext = ReplayArchiveKey::new(key).open_payload(bytes.as_ref(), BINDING, SESSION, 1024, 1024).unwrap();
    assert_eq!(plaintext.as_slice(), b"recorded plaintext\0\xff");
}

#[test]
fn every_single_bit_change_and_every_truncated_prefix_is_refused() {
    let (session, _) = captured();
    let bytes = sealer().seal_session(&session, BINDING, 65_536).unwrap();
    let key = ReplayArchiveKey::new(KEY);
    for length in 0..bytes.as_ref().len() {
        assert!(key.open_session(&bytes.as_ref()[..length], BINDING, 65_536, limits()).is_err(), "prefix {length}");
    }
    for index in 0..bytes.as_ref().len() {
        for bit in 0..8 {
            let mut changed = bytes.as_ref().to_vec();
            changed[index] ^= 1 << bit;
            assert!(key.open_session(&changed, BINDING, 65_536, limits()).is_err(), "byte {index} bit {bit}");
        }
    }
}

#[test]
fn wrong_key_and_independently_expected_identities_are_rejected() {
    let (session, _) = captured();
    let bytes = sealer().seal_session(&session, BINDING, 65_536).unwrap();
    assert!(matches!(ReplayArchiveKey::new([9; 32]).open_session(bytes.as_ref(), BINDING, 65_536, limits()), Err(ReplayArchiveError::Authentication)));
    for field in 0..2 {
        let mut binding = BINDING;
        if field == 0 { binding.source[0] ^= 1; } else { binding.capture[0] ^= 1; }
        let key = ReplayArchiveKey::new(KEY);
        assert!(matches!(key.open_session(bytes.as_ref(), binding, 65_536, limits()), Err(ReplayArchiveError::Authentication)));
        // Altering the envelope to match a substituted expected identity is not
        // sufficient: all header bytes participate in the authentication tag.
        let mut changed = bytes.as_ref().to_vec();
        changed[48..80].copy_from_slice(&binding.source);
        changed[80..HEADER].copy_from_slice(&binding.capture);
        assert!(matches!(key.open_session(&changed, binding, 65_536, limits()), Err(ReplayArchiveError::Authentication)));
    }
}

#[test]
fn exact_limits_pass_and_smaller_limits_refuse_without_consuming_the_tape() {
    let (session, _) = captured();
    let plain = session.to_canonical_bytes(65_536).unwrap();
    let length = plain.as_ref().len() + OVERHEAD;
    let mut sealer = sealer();
    assert!(sealer.seal_session(&session, BINDING, length - 1).is_err());
    assert_eq!(sealer.next, Some(0));
    let bytes = sealer.seal_session(&session, BINDING, length).unwrap();
    let key = ReplayArchiveKey::new(KEY);
    let mut bound = limits();
    bound.max_encoded_bytes = plain.as_ref().len();
    key.open_session(bytes.as_ref(), BINDING, length, bound).unwrap();
    assert!(matches!(key.open_session(bytes.as_ref(), BINDING, length - 1, bound), Err(ReplayArchiveError::EncodedLimit)));
    bound.max_encoded_bytes -= 1;
    assert!(matches!(key.open_session(bytes.as_ref(), BINDING, length, bound), Err(ReplayArchiveError::PlaintextLimit)));
    assert_eq!(session.to_canonical_bytes(65_536).unwrap().as_ref(), plain.as_ref());
}

#[test]
fn malformed_lengths_reserved_flags_and_trailing_bytes_are_rejected() {
    let (session, _) = captured();
    let bytes = sealer().seal_session(&session, BINDING, 65_536).unwrap();
    let key = ReplayArchiveKey::new(KEY);
    let mut changed = bytes.as_ref().to_vec();
    changed.extend_from_slice(bytes.as_ref());
    assert!(matches!(key.open_session(&changed, BINDING, 65_536, limits()), Err(ReplayArchiveError::Length)));
    let mut changed = bytes.as_ref().to_vec();
    changed[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(key.open_session(&changed, BINDING, 65_536, limits()), Err(ReplayArchiveError::Length)));
    for index in [8, 12, 13, 14, 15] {
        let mut changed = bytes.as_ref().to_vec();
        changed[index] ^= 0x80;
        assert!(matches!(key.open_session(&changed, BINDING, 65_536, limits()), Err(ReplayArchiveError::Format)));
    }
}

#[test]
fn nonce_counter_does_not_repeat_and_exhaustion_is_permanent() {
    let (session, _) = captured();
    let mut sealer = sealer();
    let first = sealer.seal_session(&session, BINDING, 65_536).unwrap();
    let second = sealer.seal_session(&session, BINDING, 65_536).unwrap();
    assert_eq!(&first.as_ref()[24..40], &second.as_ref()[24..40]);
    assert_eq!(&first.as_ref()[40..48], &0_u64.to_le_bytes());
    assert_eq!(&second.as_ref()[40..48], &1_u64.to_le_bytes());
    assert_ne!(first.as_ref(), second.as_ref());
    sealer.next = Some(u64::MAX);
    let last = sealer.seal_session(&session, BINDING, 65_536).unwrap();
    assert_eq!(&last.as_ref()[40..48], &u64::MAX.to_le_bytes());
    for _ in 0..2 {
        assert!(matches!(sealer.seal_session(&session, BINDING, 65_536), Err(ReplayArchiveError::NonceExhausted)));
    }
    ReplayArchiveKey::new(KEY).open_session(last.as_ref(), BINDING, 65_536, limits()).unwrap();
}

#[test]
fn authentication_precedes_canonical_decoding_and_there_is_no_plaintext_fallback() {
    let key = ReplayArchiveKey::new(KEY);
    let malformed = sealer().seal_payload(b"not a session", BINDING, SESSION, 1024).unwrap();
    assert!(matches!(key.open_session(malformed.as_ref(), BINDING, 1024, limits()), Err(ReplayArchiveError::Session(SessionTapeError::Truncated))));
    let mut changed = malformed.as_ref().to_vec();
    changed[HEADER] ^= 1;
    assert!(matches!(key.open_session(&changed, BINDING, 1024, limits()), Err(ReplayArchiveError::Authentication)));
    let (session, _) = captured();
    let plaintext = session.to_canonical_bytes(65_536).unwrap();
    assert!(matches!(key.open_session(plaintext.as_ref(), BINDING, 65_536, limits()), Err(ReplayArchiveError::Format)));
}

#[test]
fn authenticated_tapes_still_enforce_all_decoded_component_budgets() {
    let (session, _) = captured();
    let bytes = sealer().seal_session(&session, BINDING, 65_536).unwrap();
    for component in 0..3 {
        let mut limits = limits();
        match component {
            0 => limits.io.max_decoded_bytes = 0,
            1 => limits.entropy.max_decoded_bytes = 0,
            _ => limits.clock.max_decoded_bytes = 0,
        }
        assert!(matches!(ReplayArchiveKey::new(KEY).open_session(bytes.as_ref(), BINDING, 65_536, limits), Err(ReplayArchiveError::Session(_))));
    }
}

#[test]
fn authentication_does_not_mean_replay_consumed_the_entire_capture() {
    let (session, _) = captured();
    let bytes = sealer().seal_session(&session, BINDING, 65_536).unwrap();
    let restored = ReplayArchiveKey::new(KEY).open_session(bytes.as_ref(), BINDING, 65_536, limits()).unwrap();
    assert!(futures_lite::future::block_on(restored.replay().run(2, |_| Box::pin(async {}))).is_err());
}

#[test]
fn key_sealer_binding_and_archive_debug_never_expose_content() {
    let (session, _) = captured();
    let key = ReplayArchiveKey::new(KEY);
    let mut sealer = sealer();
    let bytes = sealer.seal_session(&session, BINDING, 65_536).unwrap();
    let debug = format!("{key:?} {sealer:?} {BINDING:?} {bytes:?}");
    assert!(!debug.contains(&hex::encode(KEY)));
    for secret in ["secret-request", "pong", "ASUPENC"] {
        assert!(!debug.contains(secret));
    }
    assert!(debug.contains("encrypted_bytes"));
}
