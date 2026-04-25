//! Regression test ensuring bracket releases on cancellation.

use asupersync::combinator::bracket::bracket;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};

struct PendingOnce {
    polled: bool,
}

impl Future for PendingOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.polled {
            Poll::Ready(())
        } else {
            self.polled = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

#[test]
fn bracket_release_runs_when_future_is_dropped_during_use() {
    let released = Arc::new(AtomicBool::new(false));
    let release_flag = Arc::clone(&released);

    let bracket_fut = bracket(
        async { Ok::<_, ()>(()) },
        |()| async {
            PendingOnce { polled: false }.await;
            Ok::<_, ()>(())
        },
        move |()| {
            release_flag.store(true, Ordering::SeqCst);
            async {}
        },
    );

    let mut boxed = Box::pin(bracket_fut);
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);

    assert!(
        boxed.as_mut().poll(&mut cx).is_pending(),
        "bracket future should be pending during the use phase"
    );
    assert!(!released.load(Ordering::SeqCst));

    drop(boxed);

    assert!(
        released.load(Ordering::SeqCst),
        "dropping during use should synchronously run release"
    );
}
