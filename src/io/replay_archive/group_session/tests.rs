use super::*;
use crate::io::replay::{IoCaptureLimits, IoTapeDecodeLimits};
use crate::io::replay_group::{IoGroupCaptureLimits, IoGroupDecodeLimits, IoRecordingGroup};
use crate::io::replay_group_session::{GroupSessionCaptureLimits, RecordingGroupSession};
use crate::time::{TimeSource, VirtualClock};
use crate::time::replay::TimeTapeDecodeLimits;
use crate::util::DetEntropy;
use crate::util::entropy::EntropySource;
use crate::util::entropy_replay::{EntropyCaptureLimits, EntropyTapeDecodeLimits};
use std::sync::Arc;

// Public test fixtures, never production keys or nonce allocation policy.
const KEY: [u8; 32] = [83; 32];
fn binding() -> ReplayArchiveBinding { ReplayArchiveBinding { source: [21; 32], capture: [22; 32] } }
fn limits() -> GroupSessionDecodeLimits {
    GroupSessionDecodeLimits {
        max_encoded_bytes: 65_536, max_streams: 8, max_effects: 64, max_group_bytes: 65_536,
        per_stream: IoTapeDecodeLimits::new(8192, IoCaptureLimits::new(64, 4096, 4096, 8), 8192),
        entropy: EntropyTapeDecodeLimits::new(8192, EntropyCaptureLimits::new(64, 4096, 8), 8192),
        clock: TimeTapeDecodeLimits::new(8192, 64, 4096),
    }
}
fn capture() -> RecordedGroupSession {
    let session = RecordingGroupSession::new(Arc::new(DetEntropy::new(73)), Arc::new(VirtualClock::new()), GroupSessionCaptureLimits {
        max_streams: 0, max_effects: 16, per_stream: IoCaptureLimits::new(0, 0, 0, 0),
        entropy: EntropyCaptureLimits::new(8, 64, 1), clock_observations: 8,
    }).unwrap();
    session.entropy().next_u64(); session.clock().now(); session.finish().unwrap()
}

#[test]
fn authenticated_joint_capture_restores_all_effects_without_any_original_source() {
    let capture = capture();
    let mut sealer = ReplayArchiveKey::new(KEY).into_sealer([51; 16]);
    let encrypted = sealer.seal_group_session(&capture, binding(), 65_536).unwrap();
    assert_eq!(encrypted.as_ref()[12], GROUP_SESSION);
    drop(capture); drop(sealer);
    let replay = ReplayArchiveKey::new(KEY).open_group_session(encrypted.as_ref(), binding(), 65_536, limits()).unwrap().replay();
    replay.entropy().try_next_u64().unwrap(); replay.clock().try_now().unwrap();
    replay.verify_complete().unwrap();
}

#[test]
fn wrong_key_binding_and_altered_ciphertext_authenticate_before_nested_decoding() {
    let mut sealer = ReplayArchiveKey::new(KEY).into_sealer([52; 16]);
    let encrypted = sealer.seal_group_session(&capture(), binding(), 65_536).unwrap();
    let key = ReplayArchiveKey::new(KEY);
    let wrong = ReplayArchiveKey::new([84; 32]);
    assert!(matches!(wrong.open_group_session(encrypted.as_ref(), binding(), 65_536, limits()), Err(GroupSessionArchiveError::Archive(ReplayArchiveError::Authentication))));
    let mut expected = binding(); expected.capture[0] ^= 1;
    assert!(matches!(key.open_group_session(encrypted.as_ref(), expected, 65_536, limits()), Err(GroupSessionArchiveError::Archive(ReplayArchiveError::Authentication))));
    for index in [24, 48, 112, encrypted.as_ref().len() - 1] {
        let mut changed = encrypted.as_ref().to_vec(); changed[index] ^= 1;
        let mut bound = limits(); bound.max_effects = 0;
        assert!(matches!(key.open_group_session(&changed, binding(), 65_536, bound), Err(GroupSessionArchiveError::Archive(ReplayArchiveError::Authentication))), "byte {index}");
    }
}

#[test]
fn byte_only_groups_cannot_substitute_and_all_profiles_share_one_nonce_sequence() {
    let old = IoRecordingGroup::new(IoGroupCaptureLimits { max_streams: 0, max_events: 0, per_stream: IoCaptureLimits::new(0, 0, 0, 0) }).finish().unwrap();
    let mut sealer = ReplayArchiveKey::new(KEY).into_sealer([53; 16]);
    let first = sealer.seal_io_group(&old, binding(), 65_536).unwrap();
    let second = sealer.seal_group_session(&capture(), binding(), 65_536).unwrap();
    let third = sealer.seal_io_group(&old, binding(), 65_536).unwrap();
    for (counter, archive) in [first.as_ref(), second.as_ref(), third.as_ref()].iter().enumerate() {
        assert_eq!(&archive[40..48], &(counter as u64).to_le_bytes());
    }
    let key = ReplayArchiveKey::new(KEY);
    assert!(matches!(key.open_group_session(first.as_ref(), binding(), 65_536, limits()), Err(GroupSessionArchiveError::Archive(ReplayArchiveError::Format))));
    let old_limits = IoGroupDecodeLimits { max_encoded_bytes: 65_536, max_streams: 8, max_events: 64, max_group_bytes: 8192, per_stream: limits().per_stream };
    assert!(matches!(key.open_io_group(second.as_ref(), binding(), 65_536, old_limits), Err(super::super::IoGroupArchiveError::Archive(ReplayArchiveError::Format))));
    let mut substituted = first.as_ref().to_vec(); substituted[12] = GROUP_SESSION;
    assert!(matches!(key.open_group_session(&substituted, binding(), 65_536, limits()), Err(GroupSessionArchiveError::Archive(ReplayArchiveError::Authentication))));
}

#[test]
fn encrypted_plaintext_and_nested_limits_remain_independent() {
    let mut sealer = ReplayArchiveKey::new(KEY).into_sealer([54; 16]);
    let encrypted = sealer.seal_group_session(&capture(), binding(), 65_536).unwrap();
    let key = ReplayArchiveKey::new(KEY);
    assert!(matches!(key.open_group_session(encrypted.as_ref(), binding(), encrypted.as_ref().len() - 1, limits()), Err(GroupSessionArchiveError::Archive(ReplayArchiveError::EncodedLimit))));
    let mut bound = limits(); bound.max_encoded_bytes = 0;
    assert!(matches!(key.open_group_session(encrypted.as_ref(), binding(), 65_536, bound), Err(GroupSessionArchiveError::Archive(ReplayArchiveError::PlaintextLimit))));
    bound = limits(); bound.max_effects = 0;
    assert!(matches!(key.open_group_session(encrypted.as_ref(), binding(), 65_536, bound), Err(GroupSessionArchiveError::Tape(GroupSessionTapeError::Limit("effects")))));
    let invalid = sealer.seal_payload(b"not a canonical group session", binding(), GROUP_SESSION, 65_536).unwrap();
    assert!(matches!(key.open_group_session(invalid.as_ref(), binding(), 65_536, limits()), Err(GroupSessionArchiveError::Tape(_))));
}

#[test]
fn nonce_exhaustion_never_wraps_or_silently_changes_profile() {
    let mut sealer = ReplayArchiveKey::new(KEY).into_sealer([55; 16]);
    sealer.next = Some(u64::MAX);
    let last = sealer.seal_group_session(&capture(), binding(), 65_536).unwrap();
    assert_eq!(&last.as_ref()[40..48], &u64::MAX.to_le_bytes());
    assert!(matches!(sealer.seal_group_session(&capture(), binding(), 65_536), Err(GroupSessionArchiveError::Archive(ReplayArchiveError::NonceExhausted))));
}
