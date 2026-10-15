#![no_main]

use arbitrary::Arbitrary;
use asupersync::channel::oneshot::{self, RecvError, SendError, TryRecvError};
use asupersync::cx::Cx;
use asupersync::types::CancelKind;
use futures::task::noop_waker_ref;
use libfuzzer_sys::fuzz_target;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Debug, Arbitrary)]
struct CancelRecvCase {
    value: u32,
    cancel_mode: CancelMode,
    resolve_mode: ResolveMode,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum CancelMode {
    DropPending,
    PollCancelledThenDrop,
    PollCancelledTwice,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum ResolveMode {
    SendAfterCancel,
    SendWithRetryReceiverPending,
    DropReceiverBeforeSend,
    DropPermit,
    AbortPermit,
}

fuzz_target!(|case: CancelRecvCase| {
    drive_cancelled_recv_mid_send(case);
});

fn drive_cancelled_recv_mid_send(case: CancelRecvCase) {
    let send_cx = Cx::for_testing();
    let recv_cx = Cx::for_testing();
    let (sender, mut receiver) = oneshot::channel::<u32>();
    let permit = sender
        .reserve(&send_cx)
        .expect("non-cancelled sender context must reserve a permit");

    cancel_receiver_future_while_permit_outstanding(&mut receiver, &recv_cx, case.cancel_mode);

    match case.resolve_mode {
        ResolveMode::SendAfterCancel => {
            assert_send_delivers_once(permit, &mut receiver, case.value);
        }
        ResolveMode::SendWithRetryReceiverPending => {
            assert_retry_receiver_delivers_once(permit, &mut receiver, case.value);
        }
        ResolveMode::DropReceiverBeforeSend => {
            drop(receiver);
            match permit.send(case.value) {
                Err(SendError::Disconnected(returned)) => assert_eq!(returned, case.value),
                other => panic!("send after receiver drop must return Disconnected, got {other:?}"),
            }
        }
        ResolveMode::DropPermit => {
            drop(permit);
            assert_closed_without_delivery(&mut receiver);
        }
        ResolveMode::AbortPermit => {
            permit.abort();
            assert_closed_without_delivery(&mut receiver);
        }
    }
}

fn cancel_receiver_future_while_permit_outstanding(
    receiver: &mut oneshot::Receiver<u32>,
    recv_cx: &Cx,
    mode: CancelMode,
) {
    let mut recv = Box::pin(receiver.recv(recv_cx));
    assert!(
        matches!(poll_once(recv.as_mut()), Poll::Pending),
        "receiver must wait while sender holds an unresolved permit"
    );

    recv_cx.cancel_fast(CancelKind::User);

    match mode {
        CancelMode::DropPending => {}
        CancelMode::PollCancelledThenDrop => {
            assert_cancelled(poll_once(recv.as_mut()));
        }
        CancelMode::PollCancelledTwice => {
            assert_cancelled(poll_once(recv.as_mut()));
            assert!(
                matches!(
                    poll_once(recv.as_mut()),
                    Poll::Ready(Err(RecvError::PolledAfterCompletion))
                ),
                "completed cancelled recv future must fail closed on a second poll"
            );
        }
    }
}

fn assert_send_delivers_once(
    permit: oneshot::SendPermit<u32>,
    receiver: &mut oneshot::Receiver<u32>,
    value: u32,
) {
    permit
        .send(value)
        .expect("cancelled receiver future must not drop the receiver half");
    assert_eq!(receiver.try_recv(), Ok(value));
    assert_no_second_delivery(receiver);
}

fn assert_retry_receiver_delivers_once(
    permit: oneshot::SendPermit<u32>,
    receiver: &mut oneshot::Receiver<u32>,
    value: u32,
) {
    let live_cx = Cx::for_testing();
    let mut retry = Box::pin(receiver.recv(&live_cx));
    assert!(
        matches!(poll_once(retry.as_mut()), Poll::Pending),
        "retry receiver must wait until the outstanding permit commits"
    );

    permit
        .send(value)
        .expect("retry receiver must remain connected after cancelled recv future drops");

    assert_eq!(poll_once(retry.as_mut()), Poll::Ready(Ok(value)));
    assert!(
        matches!(
            poll_once(retry.as_mut()),
            Poll::Ready(Err(RecvError::PolledAfterCompletion))
        ),
        "retry recv future must not deliver the same value twice"
    );
    drop(retry);
    assert_no_second_delivery(receiver);
}

fn assert_closed_without_delivery(receiver: &mut oneshot::Receiver<u32>) {
    assert_eq!(receiver.try_recv(), Err(TryRecvError::Closed));
    assert_no_second_delivery(receiver);
}

fn assert_no_second_delivery(receiver: &mut oneshot::Receiver<u32>) {
    assert_eq!(
        receiver.try_recv(),
        Err(TryRecvError::Closed),
        "oneshot receiver must not deliver more than one value"
    );
}

fn assert_cancelled(result: Poll<Result<u32, RecvError>>) {
    assert_eq!(result, Poll::Ready(Err(RecvError::Cancelled)));
}

fn poll_once<F>(mut future: Pin<&mut F>) -> Poll<F::Output>
where
    F: Future,
{
    let mut context = Context::from_waker(noop_waker_ref());
    future.as_mut().poll(&mut context)
}
