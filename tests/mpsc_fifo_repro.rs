//! Regression coverage for MPSC sender FIFO fairness.

use asupersync::channel::mpsc;
use asupersync::channel::mpsc::SendError;
use asupersync::cx::Cx;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

#[test]
fn waiting_sender_keeps_fifo_position_against_later_try_send() {
    let (tx, mut rx) = mpsc::channel::<i32>(1);
    let cx = Cx::for_testing();

    tx.try_send(1).expect("first send");

    let waker = Waker::noop();
    let mut task_cx = Context::from_waker(waker);
    let mut sender_a = tx.reserve(&cx);
    assert!(matches!(
        Pin::new(&mut sender_a).poll(&mut task_cx),
        Poll::Pending
    ));

    let val = rx.try_recv().expect("recv 1");
    assert_eq!(val, 1);

    let result_b = tx.try_send(3);
    assert!(
        matches!(result_b, Err(SendError::Full(3))),
        "later try_send must not steal capacity from the queued waiter, got {result_b:?}"
    );

    let permit_a = match Pin::new(&mut sender_a).poll(&mut task_cx) {
        Poll::Ready(Ok(permit)) => permit,
        other => panic!("queued sender should claim the freed slot, got {other:?}"),
    };
    permit_a.send(2);

    assert_eq!(
        rx.try_recv().expect("sender A commit"),
        2,
        "oldest queued sender should commit before a later try_send"
    );
    assert!(rx.is_empty());
}
