use super::*;
use crate::io::replay::{IoCaptureLimits, IoTapeDecodeLimits};
use crate::io::replay_group_session::{
    GroupSessionCaptureLimits, GroupSessionCompletionError, GroupSessionDecodeLimits,
    RecordedGroupSession, RecordingGroupSession,
};
use crate::io::{AsyncWrite, AsyncWriteExt};
use crate::time::VirtualClock;
use crate::time::replay::TimeTapeDecodeLimits;
use crate::util::DetEntropy;
use crate::util::entropy_replay::{EntropyCaptureLimits, EntropyTapeDecodeLimits};
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

fn immediate<F: Future>(future: F) -> F::Output {
    match Box::pin(future).as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("expected completed fixture replay"),
    }
}
fn attempt() -> ConnectionAttempt { ConnectionAttempt::new(5, 7).unwrap() }

#[derive(Debug)]
struct Sink;
impl AsyncWrite for Sink {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}
fn capture(address: SocketAddr, fail: bool) -> RecordedGroupSession {
    let session = RecordingGroupSession::new(
        Arc::new(DetEntropy::new(99)), Arc::new(VirtualClock::new()),
        GroupSessionCaptureLimits {
            max_streams: 2, max_effects: 8,
            per_stream: IoCaptureLimits::new(4, 8, 8, 1),
            entropy: EntropyCaptureLimits::new(0, 0, 1), clock_observations: 0,
        },
    ).unwrap();
    let key = request_key(address);
    let result = immediate(session.connect_with(attempt(), &key, key.len(), || async {
        if fail { Err(io::Error::from(io::ErrorKind::ConnectionRefused)) } else { Ok(Sink) }
    }));
    if fail {
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
    } else {
        let mut io = result.unwrap();
        immediate(io.write_all(b"hello")).unwrap();
        io.into_inner();
    }
    session.finish().unwrap()
}
fn decode_limits() -> GroupSessionDecodeLimits {
    GroupSessionDecodeLimits {
        max_encoded_bytes: 16_384, max_streams: 2, max_effects: 8, max_group_bytes: 4096,
        per_stream: IoTapeDecodeLimits::new(8192, IoCaptureLimits::new(8, 64, 256, 3), 4096),
        entropy: EntropyTapeDecodeLimits::new(1024, EntropyCaptureLimits::new(0, 0, 1), 1024),
        clock: TimeTapeDecodeLimits::new(1024, 0, 0),
    }
}

#[test]
fn ipv4_target_has_an_independent_fixed_width_encoding() {
    let address = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 0x1234).into();
    let key = request_key(address);
    assert_eq!(&key[..16], b"ASUPTCP\0\x01\x04\x12\x34\xc0\x00\x02\x01");
    assert_eq!(&key[16..], &[0; 20]);
}

#[test]
fn ipv6_target_preserves_flow_and_scope_in_network_byte_order() {
    let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let key = request_key(SocketAddrV6::new(ip, 0xabcd, 0x1234_5678, 0x9abc_def0).into());
    assert_eq!(&key[..12], b"ASUPTCP\0\x01\x06\xab\xcd");
    assert_eq!(&key[12..28], &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(&key[28..], &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
}

#[test]
fn different_address_fields_and_families_cannot_alias() {
    let ip = Ipv6Addr::LOCALHOST;
    let addresses = [
        SocketAddr::from(([127, 0, 0, 1], 80)),
        SocketAddr::from(([127, 0, 0, 1], 81)),
        SocketAddr::from(([127, 0, 0, 2], 80)),
        SocketAddrV6::new(Ipv4Addr::LOCALHOST.to_ipv6_mapped(), 80, 0, 0).into(),
        SocketAddrV6::new(ip, 80, 0, 0).into(),
        SocketAddrV6::new(ip, 80, 1, 0).into(),
        SocketAddrV6::new(ip, 80, 0, 1).into(),
    ];
    for (i, address) in addresses.iter().enumerate() {
        for other in &addresses[..i] { assert_ne!(request_key(*address), request_key(*other)); }
    }
    assert_eq!(request_key("[::1]:80".parse().unwrap()), request_key("[0:0:0:0:0:0:0:1]:80".parse().unwrap()));
}

#[test]
fn changed_tcp_target_fails_before_exposing_the_recorded_stream() {
    let original: SocketAddr = "127.0.0.1:8000".parse().unwrap();
    let replay = capture(original, false).replay();
    let changed = "127.0.0.1:8001".parse().unwrap();
    assert!(immediate(replay.connect_tcp(attempt(), changed)).is_err());
    assert!(matches!(replay.verify_complete(), Err(GroupSessionCompletionError::Diverged(_))));
}

#[test]
fn successful_tcp_target_replays_through_existing_canonical_bytes() {
    let address = SocketAddr::from(([192, 0, 2, 17], 9443));
    let tape = capture(address, false);
    let bytes = tape.to_canonical_bytes(16_384).unwrap();
    drop(tape);
    let replay = RecordedGroupSession::from_canonical_bytes(bytes.as_ref(), decode_limits()).unwrap().replay();
    let mut stream = immediate(replay.connect_tcp(attempt(), address)).unwrap();
    immediate(stream.write_all(b"hello")).unwrap();
    drop(stream);
    replay.verify_complete().unwrap();
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn failed_tcp_target_replays_through_existing_authenticated_archive() {
    use crate::io::replay_archive::{ReplayArchiveBinding, ReplayArchiveKey};
    let address = SocketAddr::from(([192, 0, 2, 19], 8000));
    let tape = capture(address, true);
    let binding = ReplayArchiveBinding { source: [81; 32], capture: [82; 32] };
    // Public test-only key; not production key-management guidance.
    let mut sealer = ReplayArchiveKey::new([83; 32]).into_sealer([84; 16]);
    let bytes = sealer.seal_group_session(&tape, binding, 16_384).unwrap();
    drop(tape);
    let replay = ReplayArchiveKey::new([83; 32])
        .open_group_session(bytes.as_ref(), binding, 16_384, decode_limits()).unwrap().replay();
    assert_eq!(immediate(replay.connect_tcp(attempt(), address)).unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
    replay.verify_complete().unwrap();
}

#[test]
fn flow_and_scope_changes_are_rejected_even_when_the_textual_host_is_identical() {
    let address = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 7, 9);
    for changed in [SocketAddrV6::new(*address.ip(), 80, 8, 9), SocketAddrV6::new(*address.ip(), 80, 7, 10)] {
        let replay = capture(address.into(), false).replay();
        assert!(immediate(replay.connect_tcp(attempt(), changed.into())).is_err());
        assert!(matches!(replay.verify_complete(), Err(GroupSessionCompletionError::Diverged(_))));
    }
}

#[test]
fn tcp_replay_future_preserves_send_for_region_owned_consumers() {
    fn require_send<T: Send>(value: T) -> T { value }
    let address = SocketAddr::from(([127, 0, 0, 1], 80));
    let replay = capture(address, true).replay();
    assert_eq!(immediate(require_send(replay.connect_tcp(attempt(), address))).unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
    replay.verify_complete().unwrap();
}
