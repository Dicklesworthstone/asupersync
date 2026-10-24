//! Behavioral regressions for the explicit authenticated full-object channel.

use super::*;
use super::super::{AtpFrameCodec, BytesMut, FrameTransport, FrameType, ProtocolVersion};
use crate::codec::Decoder;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

fn session(value: u8) -> RqDeltaSessionContext {
    RqDeltaSessionContext {
        session_id: [value; 32],
        destination_root: [91; 32],
    }
}

fn control(role: ControlRole, value: u8) -> AuthenticatedControl {
    AuthenticatedControl::new(
        &SecurityContext::for_testing(138),
        session(value),
        "transfer",
        role,
    )
    .unwrap()
}

fn frame(kind: FrameType) -> Frame {
    Frame::new(ProtocolVersion::CURRENT, kind, b"payload".to_vec()).unwrap()
}

fn seal(auth: &mut AuthenticatedControl, frame: &Frame) -> Frame {
    let wire = auth.prepare_send(frame).unwrap();
    auth.finish_write();
    AtpFrameCodec::new()
        .decode(&mut BytesMut::from(wire.as_slice()))
        .unwrap()
        .unwrap()
}

#[test]
fn all_full_object_control_frames_authenticate_in_both_directions() {
    let mut sender = control(ControlRole::Sender, 7);
    let mut receiver = control(ControlRole::Receiver, 7);
    for kind in [
        FrameType::ObjectComplete,
        FrameType::ObjectRequest,
        FrameType::Proof,
        FrameType::KeepAlive,
        FrameType::Close,
        FrameType::Error,
        FrameType::Cancel,
    ] {
        let original = frame(kind);
        let delivered = receiver
            .verify_received(seal(&mut sender, &original))
            .unwrap();
        assert_eq!(delivered, original);
        // Includes the real KeepAlive echo pattern: the verified frame loses
        // its incoming tag before it is signed under the reverse-direction key.
        let echoed = sender
            .verify_received(seal(&mut receiver, &delivered))
            .unwrap();
        assert_eq!(echoed, original);
    }
}

#[test]
fn altered_frames_missing_tags_and_replay_are_terminal() {
    for mutation in 0..7 {
        let mut sender = control(ControlRole::Sender, 7);
        let mut receiver = control(ControlRole::Receiver, 7);
        let valid = seal(&mut sender, &frame(FrameType::ObjectRequest));
        let mut bad = valid.clone();
        match mutation {
            0 => bad.payload[0] ^= 1,
            1 => bad.header.frame_type = FrameType::Proof,
            2 => {
                bad.header.extensions.remove(&AUTH_EXTENSION);
            }
            3 => {
                bad.header.extensions.get_mut(&AUTH_EXTENSION).unwrap()[8] ^= 1;
            }
            4 => {
                bad.header.extensions.get_mut(&AUTH_EXTENSION).unwrap()[7] = 1;
            }
            5 => {
                bad.header.extensions.insert(0x5252, vec![1]);
            }
            6 => {
                receiver.verify_received(valid.clone()).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            receiver.verify_received(bad),
            Err(RqError::Authentication(_))
        ));
        assert!(matches!(
            receiver.verify_received(valid),
            Err(RqError::Authentication(_))
        ));
    }
}

#[test]
fn directional_and_session_keys_reject_reflection_and_cross_transfer_replay() {
    let mut sender = control(ControlRole::Sender, 7);
    let packet = seal(&mut sender, &frame(FrameType::ObjectComplete));
    for (role, value) in [(ControlRole::Sender, 7), (ControlRole::Receiver, 8)] {
        assert!(matches!(
            control(role, value).verify_received(packet.clone()),
            Err(RqError::Authentication(_))
        ));
    }
    let context = SecurityContext::for_testing(138);
    for (bound_session, transfer) in [
        (session(7), "other-transfer"),
        (RqDeltaSessionContext { destination_root: [92; 32], ..session(7) }, "transfer"),
    ] {
        let mut other =
            AuthenticatedControl::new(&context, bound_session, transfer, ControlRole::Receiver)
                .unwrap();
        assert!(other.verify_received(packet.clone()).is_err());
    }
    let symbol = Symbol::new(
        SymbolId::new(ObjectId::new(1, 2), 0, 3),
        b"source or repair bytes".to_vec(),
        SymbolKind::Source,
    );
    let first = symbol_context(&context, session(7), "transfer").unwrap();
    let tag = first.sign_symbol_tag(&symbol);
    let mut same = AuthenticatedSymbol::from_parts(symbol.clone(), tag);
    first.verify_authenticated_symbol(&mut same).unwrap();
    assert!(same.is_verified());
    for other in [
        symbol_context(&context, session(8), "transfer").unwrap(),
        symbol_context(&context, session(7), "other-transfer").unwrap(),
        context,
    ] {
        let mut replayed = AuthenticatedSymbol::from_parts(symbol.clone(), tag);
        assert!(other.verify_authenticated_symbol(&mut replayed).is_err());
        assert!(!replayed.is_verified());
    }
}

#[derive(Default)]
struct TestIo {
    input: Vec<u8>,
    read_offset: usize,
    read_error: Option<std::io::ErrorKind>,
    eof: bool,
    output: Vec<u8>,
    write_limit: Option<usize>,
    pending_flush: bool,
}

impl AsyncRead for TestIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(kind) = self.read_error {
            return Poll::Ready(Err(std::io::Error::from(kind)));
        }
        let remaining = &self.input[self.read_offset..];
        let take = remaining.len().min(buf.remaining());
        if take == 0 {
            return if self.eof {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            };
        }
        buf.put_slice(&remaining[..take]);
        self.read_offset += take;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TestIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let take = self.write_limit.map_or(buf.len(), |limit| limit.min(buf.len()));
        if take == 0 {
            return Poll::Pending;
        }
        self.output.extend_from_slice(&buf[..take]);
        if let Some(limit) = &mut self.write_limit {
            *limit -= take;
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.pending_flush {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn transport(io: TestIo, role: ControlRole) -> FrameTransport<TestIo> {
    let mut transport = FrameTransport::new(io);
    transport
        .enable_authenticated_control(
            &SecurityContext::for_testing(138),
            session(7),
            "transfer",
            role,
        )
        .unwrap();
    transport
}

#[test]
fn transport_ready_and_stashed_frames_are_verified_exactly_once() {
    let mut sender = control(ControlRole::Sender, 7);
    let first = frame(FrameType::KeepAlive);
    let second = frame(FrameType::ObjectComplete);
    let mut wire = seal(&mut sender, &first).to_wire_bytes().unwrap();
    wire.extend_from_slice(&seal(&mut sender, &second).to_wire_bytes().unwrap());
    let mut receiver = transport(
        TestIo { input: wire, ..TestIo::default() },
        ControlRole::Receiver,
    );
    let ready = futures_lite::future::block_on(receiver.try_recv_ready())
        .unwrap()
        .unwrap();
    assert_eq!(ready, first);
    receiver.stashed = Some(ready);
    assert_eq!(futures_lite::future::block_on(receiver.recv()).unwrap(), first);
    assert_eq!(futures_lite::future::block_on(receiver.recv()).unwrap(), second);
    assert_eq!(
        receiver.authenticated_control.as_ref().unwrap().receive_sequence,
        2
    );
}

#[test]
fn dropping_a_partial_write_or_flush_fences_future_control_use() {
    for pending_flush in [false, true] {
        let mut sender = transport(
            TestIo {
                write_limit: (!pending_flush).then_some(3),
                pending_flush,
                ..TestIo::default()
            },
            ControlRole::Sender,
        );
        let message = frame(FrameType::ObjectComplete);
        let mut send = Box::pin(sender.send(&message));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(send.as_mut().poll(&mut cx).is_pending());
        drop(send);
        let written = sender.stream.output.len();
        assert!(written > 0, "the send really started before cancellation");
        assert!(matches!(
            futures_lite::future::block_on(sender.send(&message)),
            Err(RqError::Authentication(_))
        ));
        assert_eq!(sender.stream.output.len(), written);
    }
}

#[test]
fn authenticated_sequence_exhaustion_never_wraps() {
    let mut sender = control(ControlRole::Sender, 7);
    sender.send_sequence = u64::MAX;
    assert!(matches!(
        sender.prepare_send(&frame(FrameType::Close)),
        Err(RqError::Authentication(_))
    ));
    assert!(sender.ensure_healthy().is_err());
}

#[test]
fn udp_control_pump_fences_read_errors_and_eof() {
    let runtime = crate::runtime::RuntimeBuilder::multi_thread()
        .worker_threads(2)
        .enable_platform_reactor(true)
        .build()
        .unwrap();
    runtime.block_on(runtime.handle().spawn(async {
        use super::super::{RqDatagramRoundStats, RqReceiverUdpFanout, pump_until_control};
        let cx = crate::cx::Cx::current().unwrap();
        for kind in [std::io::ErrorKind::UnexpectedEof, std::io::ErrorKind::ConnectionReset] {
            let eof = kind == std::io::ErrorKind::UnexpectedEof;
            let mut control = transport(
                TestIo {
                    eof,
                    read_error: (!eof).then_some(kind),
                    ..TestIo::default()
                },
                ControlRole::Receiver,
            );
            let mut udp =
                RqReceiverUdpFanout::bind("127.0.0.1".parse().unwrap(), 1, 64 * 1024)
                    .await
                    .unwrap();
            let mut buffer = [0u8; 512];
            let mut accepted = 0;
            let mut stats = RqDatagramRoundStats::default();
            let failure = pump_until_control(
                &cx,
                &mut control,
                &mut udp,
                0,
                true,
                None,
                &mut buffer,
                &mut [],
                256,
                &mut accepted,
                &mut stats,
                false,
            )
            .await
            .unwrap_err();
            assert!(matches!(failure, RqError::Io(ref error) if error.kind() == kind));
            assert!(matches!(control.recv().await, Err(RqError::Authentication(_))));
            assert!(matches!(
                control.send(&frame(FrameType::Close)).await,
                Err(RqError::Authentication(_))
            ));
        }
    }));
    assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(5)));
}
