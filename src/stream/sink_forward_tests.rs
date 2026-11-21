//! Native Sink forwarding: ownership, cancellation, framing and finish boundaries.

use super::*;
use crate::stream::iter;
use crate::types::CancelKind;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::marker::PhantomPinned;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Wake;

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn counter() -> (Arc<WakeCount>, Waker) {
    crate::test_utils::init_test_logging();
    let count = Arc::new(WakeCount::default());
    (Arc::clone(&count), Waker::from(count))
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    crate::test_utils::init_test_logging();
    future.poll(&mut Context::from_waker(Waker::noop()))
}

struct SourceState<T> {
    items: VecDeque<T>,
    finished: bool,
    eof_seen: bool,
    polls: usize,
    panic_after_pop: bool,
    waker: Option<Waker>,
}

struct ControlledSource<T>(Rc<RefCell<SourceState<T>>>);

fn source<T>(items: impl IntoIterator<Item = T>, finished: bool) -> ControlledSource<T> {
    ControlledSource(Rc::new(RefCell::new(SourceState {
        items: items.into_iter().collect(),
        finished,
        eof_seen: false,
        polls: 0,
        panic_after_pop: false,
        waker: None,
    })))
}

impl<T> Stream for ControlledSource<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<T>> {
        let mut state = self.0.borrow_mut();
        assert!(!state.eof_seen, "the source must never be polled after EOF");
        state.polls += 1;
        let item = state.items.pop_front();
        assert!(
            !state.panic_after_pop,
            "provider panic after source progress"
        );
        if item.is_some() {
            Poll::Ready(item)
        } else if state.finished {
            state.eof_seen = true;
            Poll::Ready(None)
        } else {
            state.waker = Some(task.waker().clone());
            Poll::Pending
        }
    }
}

struct SinkState<T> {
    items: Vec<T>,
    ready: bool,
    flush_ready: bool,
    close_ready: bool,
    admitted: bool,
    calls: [usize; 4],
    fail: Option<SinkForwardStage>,
    panic: Option<SinkForwardStage>,
    cancel_on_ready: Option<Cx>,
    waker: Option<Waker>,
}

impl<T> SinkState<T> {
    fn fault(&self, stage: SinkForwardStage) -> io::Result<()> {
        assert_ne!(
            self.panic,
            Some(stage),
            "provider panic after sink progress"
        );
        if self.fail == Some(stage) {
            Err(io::Error::other("scripted sink failure"))
        } else {
            Ok(())
        }
    }
}

struct ControlledSink<T>(Rc<RefCell<SinkState<T>>>);

fn sink<T>() -> ControlledSink<T> {
    ControlledSink(Rc::new(RefCell::new(SinkState {
        items: Vec::new(),
        ready: true,
        flush_ready: true,
        close_ready: true,
        admitted: false,
        calls: [0; 4],
        fail: None,
        panic: None,
        cancel_on_ready: None,
        waker: None,
    })))
}

impl<T> Sink<T> for ControlledSink<T> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.borrow_mut();
        state.calls[0] += 1;
        state.fault(SinkForwardStage::Ready)?;
        if !state.ready {
            state.waker = Some(task.waker().clone());
            return Poll::Pending;
        }
        state.admitted = true;
        let cancel = state.cancel_on_ready.take();
        drop(state);
        if let Some(cx) = cancel {
            cx.cancel_fast(CancelKind::User);
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        assert!(state.admitted, "each item needs its own readiness check");
        state.admitted = false;
        state.calls[1] += 1;
        // Failure deliberately follows a side effect: generic Sink errors
        // cannot promise to return this value or undo publication.
        state.items.push(item);
        state.fault(SinkForwardStage::Send)
    }

    fn poll_flush(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.borrow_mut();
        state.calls[2] += 1;
        state.fault(SinkForwardStage::Flush)?;
        if state.flush_ready {
            Poll::Ready(Ok(()))
        } else {
            state.waker = Some(task.waker().clone());
            Poll::Pending
        }
    }

    fn poll_close(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.borrow_mut();
        state.calls[3] += 1;
        state.fault(SinkForwardStage::Close)?;
        if state.close_ready {
            Poll::Ready(Ok(()))
        } else {
            state.waker = Some(task.waker().clone());
            Poll::Pending
        }
    }
}

#[test]
fn dropped_and_cancelled_backpressure_retains_exactly_one_item() {
    let cx = Cx::for_testing();
    let input = source([1, 2, 3], true);
    let input_state = Rc::clone(&input.0);
    let output = sink();
    let output_state = Rc::clone(&output.0);
    output_state.borrow_mut().ready = false;
    let mut session = SinkForwardSession::new(input, output);

    for _ in 0..4 {
        let mut run = Box::pin(session.run(&cx));
        assert!(poll_once(run.as_mut()).is_pending());
        drop(run);
        assert!(session.progress().has_pending);
        assert_eq!(session.progress().accepted_items, 0);
        assert_eq!(input_state.borrow().polls, 1);
        assert_eq!(input_state.borrow().items, VecDeque::from([2, 3]));
        assert!(cx.inner.read().cancel_waker_registrations.is_empty());
    }

    let (wakes, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut run = Box::pin(session.run(&cx));
    assert!(run.as_mut().poll(&mut task).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        run.as_mut().poll(&mut task),
        Poll::Ready(Err(SinkForwardError::Cancelled(_)))
    ));
    drop(run);
    assert!(session.progress().has_pending);
    assert!(session.progress().failed.is_none());
    assert!(cx.inner.read().cancel_waker_registrations.is_empty());

    output_state.borrow_mut().ready = true;
    let active = Cx::for_testing();
    let mut run = Box::pin(session.run(&active));
    let Poll::Ready(Ok(progress)) = poll_once(run.as_mut()) else {
        panic!("active context resumes and finishes the retained pipeline");
    };
    assert!(progress.complete);
    assert_eq!(progress.accepted_items, 3);
    assert_eq!(progress.flushed_items, 3);
    assert_eq!(output_state.borrow().items, [1, 2, 3]);
}

#[test]
fn idle_source_cancel_migrates_wakers_and_preserves_other_observers() {
    let cx = Cx::for_testing();
    let mut session = SinkForwardSession::new(source::<u8>([], false), sink());
    let (old, old_waker) = counter();
    let (current, current_waker) = counter();
    let (other, other_waker) = counter();
    let mut observer = Box::pin(cx.cancelled());
    assert!(
        observer
            .as_mut()
            .poll(&mut Context::from_waker(&other_waker))
            .is_pending()
    );
    let mut run = Box::pin(session.run(&cx));
    assert!(
        run.as_mut()
            .poll(&mut Context::from_waker(&old_waker))
            .is_pending()
    );
    assert!(
        run.as_mut()
            .poll(&mut Context::from_waker(&current_waker))
            .is_pending()
    );
    assert_eq!(cx.inner.read().cancel_waker_registrations.len(), 2);
    drop(run);
    assert_eq!(cx.inner.read().cancel_waker_registrations.len(), 1);

    let mut run = Box::pin(session.run(&cx));
    assert!(
        run.as_mut()
            .poll(&mut Context::from_waker(&current_waker))
            .is_pending()
    );
    cx.cancel_fast(CancelKind::User);
    assert_eq!(old.0.load(Ordering::SeqCst), 0);
    assert!(current.0.load(Ordering::SeqCst) > 0);
    assert!(other.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        poll_once(run.as_mut()),
        Poll::Ready(Err(SinkForwardError::Cancelled(_)))
    ));
    drop(run);
    assert_eq!(cx.inner.read().cancel_waker_registrations.len(), 1);
    assert!(poll_once(observer.as_mut()).is_ready());
    drop(observer);
    assert!(cx.inner.read().cancel_waker_registrations.is_empty());
    assert!(!session.progress().has_pending);
}

#[test]
fn cancellation_before_source_or_after_readiness_keeps_input_owned() {
    let cx = Cx::for_testing();
    let input = source([11, 22], true);
    let state = Rc::clone(&input.0);
    let output = sink();
    let output_state = Rc::clone(&output.0);
    let mut session = SinkForwardSession::new(input, output);
    cx.cancel_fast(CancelKind::User);
    let mut run = Box::pin(session.run(&cx));
    assert!(matches!(
        poll_once(run.as_mut()),
        Poll::Ready(Err(SinkForwardError::Cancelled(_)))
    ));
    drop(run);
    assert_eq!(state.borrow().polls, 0);

    let cx = Cx::for_testing();
    output_state.borrow_mut().cancel_on_ready = Some(cx.clone());
    let mut run = Box::pin(session.run(&cx));
    assert!(matches!(
        poll_once(run.as_mut()),
        Poll::Ready(Err(SinkForwardError::Cancelled(_)))
    ));
    drop(run);
    assert!(session.progress().has_pending);
    assert_eq!(state.borrow().polls, 1);
    assert!(output_state.borrow().items.is_empty());
    let active = Cx::for_testing();
    let mut run = Box::pin(session.run(&active));
    assert!(matches!(poll_once(run.as_mut()), Poll::Ready(Ok(_))));
    assert_eq!(output_state.borrow().items, [11, 22]);
}

#[test]
fn cancellation_inside_source_poll_cannot_park_or_discard_a_yielded_item() {
    struct CancelFromSource {
        cx: Cx,
        ready: bool,
    }
    impl Stream for CancelFromSource {
        type Item = u8;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<u8>> {
            self.cx.cancel_fast(CancelKind::User);
            if self.ready {
                Poll::Ready(Some(5))
            } else {
                Poll::Pending
            }
        }
    }

    for ready in [false, true] {
        let cx = Cx::for_testing();
        let input = CancelFromSource {
            cx: cx.clone(),
            ready,
        };
        let mut session = SinkForwardSession::new(input, sink());
        let mut run = Box::pin(session.run(&cx));
        assert!(matches!(
            poll_once(run.as_mut()),
            Poll::Ready(Err(SinkForwardError::Cancelled(_)))
        ));
        drop(run);
        assert_eq!(session.progress().accepted_items, 0);
        assert!(cx.inner.read().cancel_waker_registrations.is_empty());
        let (_, output, pending) = session.into_parts();
        assert_eq!(pending, ready.then_some(5));
        assert!(output.0.borrow().items.is_empty());
    }
}

#[test]
fn masked_cancellation_is_deferred_until_unmask_and_preserves_state() {
    let cx = Cx::for_testing();
    let mut session = SinkForwardSession::new(source::<u8>([], false), sink());
    let (wakes, waker) = counter();
    let mut run = Box::pin(session.run(&cx));
    cx.masked(|| {
        cx.cancel_fast(CancelKind::User);
        assert!(
            run.as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
    });
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        poll_once(run.as_mut()),
        Poll::Ready(Err(SinkForwardError::Cancelled(_)))
    ));
    drop(run);
    assert_eq!(session.progress().accepted_items, 0);
    assert!(session.progress().failed.is_none());
}

#[test]
fn idle_flush_survives_drop_and_refreshes_source_waker_on_resume() {
    let cx = Cx::for_testing();
    let input = source([7], false);
    let input_state = Rc::clone(&input.0);
    let output = sink();
    let output_state = Rc::clone(&output.0);
    output_state.borrow_mut().flush_ready = false;
    let mut session = SinkForwardSession::new(input, output);
    let (_, old_waker) = counter();
    let mut run = Box::pin(session.run(&cx));
    assert!(
        run.as_mut()
            .poll(&mut Context::from_waker(&old_waker))
            .is_pending()
    );
    drop(run);
    assert_eq!(session.progress().accepted_items, 1);
    assert_eq!(session.progress().flushed_items, 0);
    assert_eq!(input_state.borrow().polls, 2);

    output_state.borrow_mut().flush_ready = true;
    let (wakes, new_waker) = counter();
    let mut run = Box::pin(session.run(&cx));
    assert!(
        run.as_mut()
            .poll(&mut Context::from_waker(&new_waker))
            .is_pending()
    );
    assert_eq!(input_state.borrow().polls, 3);
    assert!(
        input_state
            .borrow()
            .waker
            .as_ref()
            .unwrap()
            .will_wake(&new_waker)
    );
    let source_waker = {
        let mut state = input_state.borrow_mut();
        state.items.push_back(8);
        state.finished = true;
        state.waker.take().unwrap()
    };
    source_waker.wake();
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(poll_once(run.as_mut()), Poll::Ready(Ok(_))));
    drop(run);
    assert_eq!(session.progress().flushed_items, 2);
    assert_eq!(output_state.borrow().items, [7, 8]);
}

#[test]
fn eof_flush_and_close_resume_without_repolling_source() {
    let cx = Cx::for_testing();
    let input = source([9], true);
    let input_state = Rc::clone(&input.0);
    let output = sink();
    let output_state = Rc::clone(&output.0);
    output_state.borrow_mut().flush_ready = false;
    let mut session = SinkForwardSession::new(input, output);
    let mut run = Box::pin(session.run(&cx));
    assert!(poll_once(run.as_mut()).is_pending());
    drop(run);
    assert!(session.progress().source_exhausted);
    assert_eq!(session.progress().flushed_items, 0);

    {
        let mut state = output_state.borrow_mut();
        state.flush_ready = true;
        state.close_ready = false;
    }
    let mut run = Box::pin(session.run(&cx));
    assert!(poll_once(run.as_mut()).is_pending());
    drop(run);
    assert_eq!(session.progress().flushed_items, 1);
    assert_eq!(input_state.borrow().polls, 2);
    cx.cancel_fast(CancelKind::User);
    let mut run = Box::pin(session.run(&cx));
    assert!(matches!(
        poll_once(run.as_mut()),
        Poll::Ready(Err(SinkForwardError::Cancelled(_)))
    ));
    drop(run);
    output_state.borrow_mut().close_ready = true;
    let active = Cx::for_testing();
    let mut run = Box::pin(session.run(&active));
    assert!(matches!(poll_once(run.as_mut()), Poll::Ready(Ok(_))));
    drop(run);
    let calls = output_state.borrow().calls;
    let mut run = Box::pin(session.run(&cx));
    let Poll::Ready(Ok(progress)) = poll_once(run.as_mut()) else {
        panic!("completed sessions do not reopen even with a cancelled context");
    };
    assert!(progress.complete);
    assert_eq!(output_state.borrow().calls, calls);
    assert_eq!(input_state.borrow().polls, 2);
}

#[test]
fn each_sink_error_fences_retry_and_reports_remaining_ownership() {
    for stage in [
        SinkForwardStage::Ready,
        SinkForwardStage::Send,
        SinkForwardStage::Flush,
        SinkForwardStage::Close,
    ] {
        let cx = Cx::for_testing();
        let output = sink();
        let state = Rc::clone(&output.0);
        state.borrow_mut().fail = Some(stage);
        let mut session = SinkForwardSession::new(source([10, 20], true), output);
        let mut run = Box::pin(session.run(&cx));
        assert!(matches!(
            poll_once(run.as_mut()),
            Poll::Ready(Err(SinkForwardError::Sink { stage: failed, .. })) if failed == stage
        ));
        drop(run);
        let progress = session.progress();
        assert_eq!(progress.failed, Some(stage));
        assert_eq!(progress.has_pending, stage == SinkForwardStage::Ready);
        assert_eq!(
            progress.accepted_items,
            if matches!(stage, SinkForwardStage::Ready | SinkForwardStage::Send) {
                0
            } else {
                2
            }
        );
        let calls = state.borrow().calls;
        let mut run = Box::pin(session.run(&cx));
        assert!(matches!(
            poll_once(run.as_mut()),
            Poll::Ready(Err(SinkForwardError::Failed { stage: failed })) if failed == stage
        ));
        drop(run);
        assert_eq!(state.borrow().calls, calls);
        let (input, _, pending) = session.into_parts();
        match stage {
            SinkForwardStage::Ready => {
                assert_eq!(pending, Some(10));
                assert_eq!(input.0.borrow().items, VecDeque::from([20]));
                assert!(state.borrow().items.is_empty());
            }
            SinkForwardStage::Send => {
                assert_eq!(pending, None, "Sink consumed the failed submission");
                assert_eq!(input.0.borrow().items, VecDeque::from([20]));
                assert_eq!(state.borrow().items, [10], "failure had a side effect");
            }
            _ => {
                assert_eq!(pending, None);
                assert!(input.0.borrow().items.is_empty());
                assert_eq!(state.borrow().items, [10, 20]);
            }
        }
    }
}

#[test]
fn provider_panics_after_side_effects_fence_source_and_send_repolls() {
    for stage in [SinkForwardStage::Source, SinkForwardStage::Send] {
        let cx = Cx::for_testing();
        let input = source([10, 20], true);
        let input_state = Rc::clone(&input.0);
        input_state.borrow_mut().panic_after_pop = stage == SinkForwardStage::Source;
        let output = sink();
        let output_state = Rc::clone(&output.0);
        if stage == SinkForwardStage::Send {
            output_state.borrow_mut().panic = Some(stage);
        }
        let mut session = SinkForwardSession::new(input, output);
        let mut run = Box::pin(session.run(&cx));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = poll_once(run.as_mut());
        }));
        assert!(panic.is_err());
        drop(run);
        assert_eq!(session.progress().failed, Some(stage));
        assert_eq!(session.progress().accepted_items, 0);
        let mut run = Box::pin(session.run(&cx));
        assert!(matches!(
            poll_once(run.as_mut()),
            Poll::Ready(Err(SinkForwardError::Failed { stage: failed })) if failed == stage
        ));
        drop(run);
        let (_, _, pending) = session.into_parts();
        assert_eq!(pending, None);
        assert_eq!(input_state.borrow().polls, 1);
        assert_eq!(input_state.borrow().items, VecDeque::from([20]));
        assert_eq!(
            output_state.borrow().items.len(),
            usize::from(stage == SinkForwardStage::Send)
        );
    }
}

#[test]
fn always_ready_transfer_yields_and_self_wakes_with_bounded_work() {
    let cx = Cx::for_testing();
    let output = sink();
    let state = Rc::clone(&output.0);
    let total = SENDS_PER_POLL * 3 + 5;
    let mut session = SinkForwardSession::new(iter(0..total), output);
    let (wakes, waker) = counter();
    let mut run = Box::pin(session.run(&cx));
    for batch in 1..=3 {
        assert!(
            run.as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert_eq!(state.borrow().items.len(), batch * SENDS_PER_POLL);
        assert!(wakes.0.load(Ordering::SeqCst) >= batch);
    }
    let Poll::Ready(Ok(progress)) = poll_once(run.as_mut()) else {
        panic!("finite source finishes after bounded cooperative turns");
    };
    assert_eq!(progress.accepted_items, total as u64);
    assert_eq!(state.borrow().items, (0..total).collect::<Vec<_>>());
}

#[test]
fn pinned_non_send_providers_accept_borrowed_non_clone_non_unpin_items() {
    struct Item<'a>(&'a str, PhantomPinned);
    struct PinnedSource<'a> {
        item: RefCell<Option<Item<'a>>>,
        _pin: PhantomPinned,
    }
    impl<'a> Stream for PinnedSource<'a> {
        type Item = Item<'a>;
        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.as_ref().get_ref().item.borrow_mut().take())
        }
    }
    struct PinnedSink<'a> {
        seen: Rc<RefCell<Vec<Item<'a>>>>,
        ready: Cell<bool>,
        _pin: PhantomPinned,
    }
    impl<'a> Sink<Item<'a>> for PinnedSink<'a> {
        type Error = io::Error;
        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.as_ref().get_ref().ready.set(true);
            Poll::Ready(Ok(()))
        }
        fn start_send(self: Pin<&mut Self>, item: Item<'a>) -> io::Result<()> {
            let this = self.as_ref().get_ref();
            assert!(this.ready.replace(false));
            this.seen.borrow_mut().push(item);
            Ok(())
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    let text = String::from("borrowed without cloning");
    let seen = Rc::new(RefCell::new(Vec::new()));
    let input = Box::pin(PinnedSource {
        item: RefCell::new(Some(Item(&text, PhantomPinned))),
        _pin: PhantomPinned,
    });
    let output = Box::pin(PinnedSink {
        seen: Rc::clone(&seen),
        ready: Cell::new(false),
        _pin: PhantomPinned,
    });
    let cx = Cx::for_testing();
    let mut session = SinkForwardSession::new(input, output);
    let mut run = Box::pin(session.run(&cx));
    assert!(matches!(poll_once(run.as_mut()), Poll::Ready(Ok(_))));
    assert_eq!(seen.borrow()[0].0, text);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_framed_transfer_resumes_partial_writes_and_half_closes() {
    use crate::codec::{FramedWrite, LinesCodec};
    use crate::io::{AsyncReadExt, duplex};
    use crate::runtime::RuntimeBuilder;

    for workers in [1, 2] {
        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread().build().unwrap()
        } else {
            RuntimeBuilder::multi_thread()
                .worker_threads(workers)
                .build()
                .unwrap()
        };
        runtime.block_on(async {
            let cx = Cx::for_testing();
            let (writer, mut peer) = duplex(2);
            let framed = FramedWrite::new(writer, LinesCodec::new()).with_backpressure_boundary(1);
            let mut session =
                SinkForwardSession::new(iter(["abc".to_owned(), "def".to_owned()]), framed);
            let mut run = Box::pin(session.run(&cx));
            assert!(poll_once(run.as_mut()).is_pending());
            drop(run);
            assert_eq!(session.progress().accepted_items, 1);
            assert!(session.progress().has_pending);
            assert_eq!(session.get_ref().1.write_buffer().as_ref(), b"c\n");
            let mut prefix = [0; 2];
            peer.read_exact(&mut prefix).await.unwrap();
            assert_eq!(&prefix, b"ab");
            let receive = async {
                let mut rest = Vec::new();
                peer.read_to_end(&mut rest).await.unwrap();
                rest
            };
            let (result, rest) = futures_lite::future::zip(session.run(&cx), receive).await;
            let progress = result.unwrap();
            assert!(progress.complete);
            assert_eq!(progress.accepted_items, 2);
            assert_eq!(progress.flushed_items, 2);
            assert_eq!(rest, b"c\ndef\n");
        });
        assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(5)));
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_idle_channel_flushes_before_more_input_is_available() {
    use crate::channel::mpsc;
    use crate::codec::{FramedWrite, LinesCodec};
    use crate::io::{AsyncReadExt, duplex};
    use crate::runtime::RuntimeBuilder;
    use crate::stream::ReceiverStream;

    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::for_testing();
        let (sender, receiver) = mpsc::channel(2);
        sender.try_send("request".to_owned()).unwrap();
        let input = ReceiverStream::new(cx.clone(), receiver);
        let (writer, mut peer) = duplex(64);
        let mut session =
            SinkForwardSession::new(input, FramedWrite::new(writer, LinesCodec::new()));
        let conversation = async {
            let mut first = [0; 8];
            peer.read_exact(&mut first).await.unwrap();
            assert_eq!(&first, b"request\n");
            // The next input depends on observing the first wire frame. A
            // forwarder that waits for the 8KiB boundary or EOF cannot proceed.
            sender.try_send("response".to_owned()).unwrap();
            drop(sender);
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest).await.unwrap();
            assert_eq!(rest, b"response\n");
        };
        let (result, ()) = futures_lite::future::zip(session.run(&cx), conversation).await;
        let progress = result.unwrap();
        assert!(progress.complete);
        assert_eq!(progress.flushed_items, 2);
    });
    assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(5)));
}

#[derive(Debug)]
struct SourceFailure(Rc<()>);

impl std::fmt::Display for SourceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original source failure")
    }
}

impl std::error::Error for SourceFailure {}

#[test]
fn try_forward_source_error_retains_unflushed_prefix_and_fences_both_providers() {
    let cx = Cx::for_testing();
    let marker = Rc::new(());
    let input = source(
        [Ok(10), Err(SourceFailure(Rc::clone(&marker))), Ok(20)],
        true,
    );
    let input_state = Rc::clone(&input.0);
    let output = sink();
    let output_state = Rc::clone(&output.0);
    let mut session = TrySinkForwardSession::new(input, output);
    let mut run = Box::pin(session.run(&cx));
    let error = match poll_once(run.as_mut()) {
        Poll::Ready(Err(error)) => error,
        other => panic!("source failure must terminate forwarding: {other:?}"),
    };
    let preserved = std::error::Error::source(&error)
        .and_then(|source| source.downcast_ref::<SourceFailure>())
        .expect("source error remains available through Error::source");
    assert!(Rc::ptr_eq(&preserved.0, &marker));
    assert!(matches!(error, TrySinkForwardError::Source(_)));
    drop(run);
    assert_eq!(
        session.progress(),
        SinkForwardProgress {
            accepted_items: 1,
            flushed_items: 0,
            has_pending: false,
            source_exhausted: false,
            complete: false,
            failed: Some(SinkForwardStage::Source),
        }
    );
    assert_eq!(output_state.borrow().items, [10]);
    assert_eq!(output_state.borrow().calls, [1, 1, 0, 0]);
    assert_eq!(input_state.borrow().polls, 2);
    cx.cancel_fast(CancelKind::User);
    let mut run = Box::pin(session.run(&cx));
    assert!(matches!(
        poll_once(run.as_mut()),
        Poll::Ready(Err(TrySinkForwardError::Failed {
            stage: SinkForwardStage::Source
        }))
    ));
    drop(run);
    assert_eq!(output_state.borrow().calls, [1, 1, 0, 0]);
    assert_eq!(input_state.borrow().polls, 2);
    let (input, _, pending) = session.into_parts();
    assert_eq!(pending, None);
    assert!(matches!(input.0.borrow().items.front(), Some(Ok(20))));
}

#[test]
fn try_forward_sink_errors_keep_their_type_stage_and_ownership_boundary() {
    for stage in [
        SinkForwardStage::Ready,
        SinkForwardStage::Send,
        SinkForwardStage::Flush,
        SinkForwardStage::Close,
    ] {
        let cx = Cx::for_testing();
        let input = source([Ok::<_, SourceFailure>(10), Ok(20)], true);
        let input_state = Rc::clone(&input.0);
        let output = sink();
        let output_state = Rc::clone(&output.0);
        output_state.borrow_mut().fail = Some(stage);
        let mut session = TrySinkForwardSession::new(input, output);
        let mut run = Box::pin(session.run(&cx));
        match poll_once(run.as_mut()) {
            Poll::Ready(Err(TrySinkForwardError::Sink {
                stage: actual,
                error,
            })) => {
                assert_eq!(actual, stage);
                assert_eq!(error.kind(), io::ErrorKind::Other);
                assert_eq!(error.to_string(), "scripted sink failure");
            }
            other => panic!("sink failure was misclassified: {other:?}"),
        }
        drop(run);
        let progress = session.progress();
        assert_eq!(progress.failed, Some(stage));
        assert!(!progress.complete);
        assert_eq!(progress.has_pending, stage == SinkForwardStage::Ready);
        assert_eq!(
            progress.accepted_items,
            if matches!(stage, SinkForwardStage::Ready | SinkForwardStage::Send) {
                0
            } else {
                2
            }
        );
        assert_eq!(
            progress.flushed_items,
            if stage == SinkForwardStage::Close {
                2
            } else {
                0
            }
        );
        let calls = output_state.borrow().calls;
        let polls = input_state.borrow().polls;
        let mut run = Box::pin(session.run(&cx));
        assert!(matches!(poll_once(run.as_mut()), Poll::Ready(Err(
            TrySinkForwardError::Failed { stage: actual }
        )) if actual == stage));
        drop(run);
        assert_eq!(output_state.borrow().calls, calls);
        assert_eq!(input_state.borrow().polls, polls);
        let (_, _, pending) = session.into_parts();
        assert_eq!(pending, (stage == SinkForwardStage::Ready).then_some(10));
        if stage == SinkForwardStage::Send {
            assert_eq!(
                output_state.borrow().items,
                [10],
                "failed send already consumed the item"
            );
        }
    }
}

#[test]
fn try_forward_cancellation_during_source_error_preserves_the_original_error() {
    struct CancellingSource {
        cx: Cx,
        error: Option<SourceFailure>,
        polls: Rc<Cell<usize>>,
    }
    impl Stream for CancellingSource {
        type Item = Result<u8, SourceFailure>;

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.polls.set(self.polls.get() + 1);
            self.cx.cancel_fast(CancelKind::User);
            Poll::Ready(Some(Err(self
                .error
                .take()
                .expect("source must not be retried"))))
        }
    }

    let cx = Cx::for_testing();
    let marker = Rc::new(());
    let polls = Rc::new(Cell::new(0));
    let input = CancellingSource {
        cx: cx.clone(),
        error: Some(SourceFailure(Rc::clone(&marker))),
        polls: Rc::clone(&polls),
    };
    let output = sink();
    let output_state = Rc::clone(&output.0);
    let mut session = TrySinkForwardSession::new(input, output);
    let mut run = Box::pin(session.run(&cx));
    match poll_once(run.as_mut()) {
        Poll::Ready(Err(TrySinkForwardError::Source(error))) => {
            assert!(Rc::ptr_eq(&error.0, &marker));
        }
        other => panic!("cancellation erased a source result: {other:?}"),
    }
    drop(run);
    assert!(cx.is_cancel_requested());
    assert!(cx.inner.read().cancel_waker_registrations.is_empty());
    let active = Cx::for_testing();
    let mut run = Box::pin(session.run(&active));
    assert!(matches!(
        poll_once(run.as_mut()),
        Poll::Ready(Err(TrySinkForwardError::Failed {
            stage: SinkForwardStage::Source
        }))
    ));
    drop(run);
    assert_eq!(polls.get(), 1);
    assert_eq!(output_state.borrow().calls, [0; 4]);
}

#[test]
fn try_forward_drop_cancel_and_resume_retains_one_borrowed_non_unpin_item() {
    struct Item<'a>(&'a str, Rc<()>, PhantomPinned);

    let text = String::from("one owned item, borrowed contents");
    let marker = Rc::new(());
    let cx = Cx::for_testing();
    let input = source(
        [Ok::<_, SourceFailure>(Item(
            &text,
            Rc::clone(&marker),
            PhantomPinned,
        ))],
        true,
    );
    let input_state = Rc::clone(&input.0);
    let output = sink();
    let output_state = Rc::clone(&output.0);
    output_state.borrow_mut().ready = false;
    let mut session = TrySinkForwardSession::new(input, output);
    for _ in 0..2 {
        let mut run = Box::pin(session.run(&cx));
        assert!(poll_once(run.as_mut()).is_pending());
        drop(run);
        assert!(session.progress().has_pending);
        assert_eq!(input_state.borrow().polls, 1);
        assert!(cx.inner.read().cancel_waker_registrations.is_empty());
    }
    let (wakes, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut run = Box::pin(session.run(&cx));
    assert!(run.as_mut().poll(&mut task).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        run.as_mut().poll(&mut task),
        Poll::Ready(Err(TrySinkForwardError::Cancelled(_)))
    ));
    drop(run);
    assert!(session.progress().has_pending);
    assert_eq!(session.progress().accepted_items, 0);
    assert_eq!(session.progress().failed, None);
    assert!(cx.inner.read().cancel_waker_registrations.is_empty());

    output_state.borrow_mut().ready = true;
    let active = Cx::for_testing();
    let mut run = Box::pin(session.run(&active));
    let Poll::Ready(Ok(progress)) = poll_once(run.as_mut()) else {
        panic!("active context must resume the same retained item");
    };
    drop(run);
    assert!(progress.complete);
    assert_eq!(progress.accepted_items, 1);
    assert_eq!(progress.flushed_items, 1);
    assert_eq!(input_state.borrow().polls, 2);
    let state = output_state.borrow();
    assert_eq!(state.items.len(), 1);
    assert_eq!(state.items[0].0, text);
    assert!(Rc::ptr_eq(&state.items[0].1, &marker));
}

#[test]
fn try_forward_idle_flush_and_eof_close_resume_at_the_same_boundaries() {
    let cx = Cx::for_testing();
    let input = source([Ok::<_, SourceFailure>(5)], false);
    let input_state = Rc::clone(&input.0);
    let output = sink();
    let output_state = Rc::clone(&output.0);
    output_state.borrow_mut().flush_ready = false;
    let mut session = TrySinkForwardSession::new(input, output);
    let mut run = Box::pin(session.run(&cx));
    assert!(poll_once(run.as_mut()).is_pending());
    drop(run);
    assert_eq!(session.progress().accepted_items, 1);
    assert_eq!(session.progress().flushed_items, 0);
    assert!(!session.progress().source_exhausted);
    assert_eq!(output_state.borrow().calls[3], 0);

    output_state.borrow_mut().flush_ready = true;
    let (wakes, waker) = counter();
    let mut run = Box::pin(session.run(&cx));
    assert!(
        run.as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(run);
    assert_eq!(session.progress().flushed_items, 1);
    assert_eq!(
        input_state.borrow().polls,
        3,
        "resume must refresh the source wake"
    );
    let source_waker = {
        let mut state = input_state.borrow_mut();
        state.items.push_back(Ok(6));
        state.finished = true;
        state.waker.take().expect("source registered its new wake")
    };
    source_waker.wake();
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    output_state.borrow_mut().close_ready = false;
    let mut run = Box::pin(session.run(&cx));
    assert!(poll_once(run.as_mut()).is_pending());
    drop(run);
    assert!(session.progress().source_exhausted);
    assert!(!session.progress().complete);
    assert_eq!(session.progress().flushed_items, 2);
    assert_eq!(input_state.borrow().polls, 5);
    output_state.borrow_mut().close_ready = true;
    let mut run = Box::pin(session.run(&cx));
    assert!(matches!(poll_once(run.as_mut()), Poll::Ready(Ok(progress)) if progress.complete));
    drop(run);
    let calls = output_state.borrow().calls;
    let mut run = Box::pin(session.run(&cx));
    assert!(matches!(poll_once(run.as_mut()), Poll::Ready(Ok(progress)) if progress.complete));
    drop(run);
    assert_eq!(output_state.borrow().calls, calls);
    assert_eq!(output_state.borrow().items, [5, 6]);
    assert_eq!(input_state.borrow().polls, 5, "close never repolls EOF");
}

#[test]
fn ordinary_forward_preserves_result_items_including_errors() {
    let cx = Cx::for_testing();
    let input = source([Ok(1), Err("ordinary item"), Ok(2)], true);
    let output = sink();
    let state = Rc::clone(&output.0);
    let mut session = SinkForwardSession::new(input, output);
    let mut run = Box::pin(session.run(&cx));
    let Poll::Ready(Ok(progress)) = poll_once(run.as_mut()) else {
        panic!("the ordinary forwarding API must not reinterpret Result items");
    };
    assert!(progress.complete);
    assert_eq!(progress.accepted_items, 3);
    assert_eq!(progress.flushed_items, 3);
    assert_eq!(state.borrow().items, [Ok(1), Err("ordinary item"), Ok(2)]);
    assert_eq!(state.borrow().calls, [3, 3, 1, 1]);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_try_forward_reader_stream_preserves_bytes_and_half_close() {
    use crate::codec::{BytesCodec, FramedWrite};
    use crate::io::{AsyncReadExt, AsyncWriteExt, ReaderStream, duplex};
    use crate::runtime::RuntimeBuilder;

    for workers in [1, 2] {
        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread().build().unwrap()
        } else {
            RuntimeBuilder::multi_thread()
                .worker_threads(workers)
                .build()
                .unwrap()
        };
        runtime.block_on(async {
            let cx = Cx::for_testing();
            let (mut producer, reader) = duplex(3);
            let (writer, mut peer) = duplex(2);
            let source = ReaderStream::with_capacity(reader, 4);
            let sink = FramedWrite::new(writer, BytesCodec::new()).with_backpressure_boundary(1);
            let mut session = TrySinkForwardSession::new(source, sink);
            let mut run = Box::pin(session.run(&cx));
            assert!(poll_once(run.as_mut()).is_pending());
            drop(run);
            assert_eq!(session.progress().accepted_items, 0);
            let expected = b"native fallible streams retain every byte across backpressure";
            let sending = async {
                producer.write_all(expected).await.unwrap();
                producer.shutdown().await.unwrap();
            };
            let receiving = async {
                let mut bytes = Vec::new();
                peer.read_to_end(&mut bytes).await.unwrap();
                bytes
            };
            let ((result, ()), bytes) = futures_lite::future::zip(
                futures_lite::future::zip(session.run(&cx), sending),
                receiving,
            )
            .await;
            let progress = result.unwrap();
            assert!(progress.complete);
            assert!(progress.accepted_items > 1);
            assert_eq!(progress.accepted_items, progress.flushed_items);
            assert_eq!(bytes, expected);
            let (_, mut sink, pending) = session.into_parts();
            assert!(pending.is_none());
            assert!(sink.write_buffer().is_empty());
            // Closing the forwarded sending side must leave reverse I/O open.
            peer.write_all(b"ok").await.unwrap();
            let mut reply = [0; 2];
            sink.get_mut().read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"ok");
        });
        assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(5)));
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_try_forward_decodes_and_reencodes_lines_with_bounded_duplex_io() {
    use crate::codec::{FramedRead, FramedWrite, LinesCodec};
    use crate::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use crate::runtime::RuntimeBuilder;

    for workers in [1, 2] {
        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread().build().unwrap()
        } else {
            RuntimeBuilder::multi_thread()
                .worker_threads(workers)
                .build()
                .unwrap()
        };
        runtime.block_on(async {
            let cx = Cx::for_testing();
            let (mut producer, reader) = duplex(3);
            let (writer, mut peer) = duplex(2);
            let source = FramedRead::new(reader, LinesCodec::new());
            let sink = FramedWrite::new(writer, LinesCodec::new()).with_backpressure_boundary(1);
            let mut session = TrySinkForwardSession::new(source, sink);
            let expected = b"alpha\nbeta\nlast\n";
            let sending = async {
                producer.write_all(expected).await.unwrap();
                producer.shutdown().await.unwrap();
            };
            let receiving = async {
                let mut bytes = Vec::new();
                peer.read_to_end(&mut bytes).await.unwrap();
                bytes
            };
            let ((result, ()), bytes) = futures_lite::future::zip(
                futures_lite::future::zip(session.run(&cx), sending),
                receiving,
            )
            .await;
            let progress = result.unwrap();
            assert!(progress.complete);
            assert!(progress.source_exhausted);
            assert_eq!(progress.accepted_items, 3);
            assert_eq!(progress.flushed_items, 3);
            assert_eq!(bytes, expected);
            let (_, mut sink, pending) = session.into_parts();
            assert!(pending.is_none());
            assert!(sink.write_buffer().is_empty());
            peer.write_all(b"ok").await.unwrap();
            let mut reply = [0; 2];
            sink.get_mut().read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"ok");
        });
        assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(5)));
    }
}
