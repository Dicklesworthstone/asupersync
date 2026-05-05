use super::mpsc::{Sender, channel};
use crate::cx::Cx;
use std::future::Future;
use std::task::{Context, Poll, Waker};

struct Msg(Option<Sender<Self>>);

impl Drop for Msg {
    fn drop(&mut self) {
        let _ = self.0.take();
    }
}

#[test]
fn dropping_receiver_with_queued_message_holding_last_sender_does_not_deadlock() {
    let (tx, rx) = channel::<Msg>(10);
    let cx = Cx::for_testing();

    // The queued message owns the only remaining sender clone. If Receiver::drop
    // drops queued items while holding the channel mutex, dropping `rx` would
    // deadlock here when `Msg::drop` drops that nested sender.
    let msg = Msg(Some(tx.clone()));
    let mut send_fut = Box::pin(tx.send(&cx, msg));
    let waker = Waker::noop();
    let mut task_cx = Context::from_waker(waker);

    let send_ready = matches!(send_fut.as_mut().poll(&mut task_cx), Poll::Ready(Ok(())));
    assert!(
        send_ready,
        "send should complete immediately for the deadlock regression setup"
    );
    drop(send_fut);

    drop(tx);
    drop(rx);
}
