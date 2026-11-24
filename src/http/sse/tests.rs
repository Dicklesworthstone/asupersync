use super::*;
use crate::bytes::{Bytes, BytesCursor};
use crate::http::body::{Full, HeaderMap};
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, CancelKind, RegionId, TaskId};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomPinned;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

fn decode_chunk(decoder: &mut SseDecoder, mut bytes: &[u8], events: &mut Vec<SseEvent>) {
    while !bytes.is_empty() {
        if let Some(event) = decoder.decode(&mut bytes).unwrap() {
            events.push(event);
        }
    }
}

#[test]
fn whatwg_fields_utf8_bom_and_all_newline_boundaries_survive_every_split() {
    let wire = b"\xef\xbb\xbf: opening\r\nid: \xce\xb1\revent: update\r\n\
data:  first\ndata: \xe2\x82\xac\rdata: \xff\r\nretry: 42\nretry: +9\nretry: 2x\n\r\n\
id: rejected\0id\nDATA: ignored\ndata\n\nid:\n\n\
data: \xef\xbb\xbfliteral\n\nid: incomplete\ndata: tail";
    let expected = vec![
        SseEvent {
            event_type: "update".to_owned(),
            data: " first\n€\n\u{fffd}".to_owned(),
            last_event_id: "α".to_owned(),
        },
        SseEvent {
            event_type: "message".to_owned(),
            data: String::new(),
            last_event_id: "α".to_owned(),
        },
        SseEvent {
            event_type: "message".to_owned(),
            data: "\u{feff}literal".to_owned(),
            last_event_id: String::new(),
        },
    ];
    for split in 0..=wire.len() {
        let mut decoder = SseDecoder::new(SseLimits::default());
        let mut events = Vec::new();
        decode_chunk(&mut decoder, &wire[..split], &mut events);
        decode_chunk(&mut decoder, &wire[split..], &mut events);
        decoder.finish();
        assert_eq!(events, expected, "wire split {split}");
        assert_eq!(decoder.last_event_id(), "");
        assert_eq!(decoder.retry_millis(), Some(42));
    }
    let mut decoder = SseDecoder::new(SseLimits::default());
    let mut events = Vec::new();
    for byte in wire {
        decode_chunk(&mut decoder, std::slice::from_ref(byte), &mut events);
    }
    decoder.finish();
    assert_eq!(events, expected);
    assert_eq!(decoder.last_event_id(), "");
}

#[test]
fn cursor_commits_only_at_blank_lines_and_retry_is_independent() {
    let mut decoder = SseDecoder::new(SseLimits::default())
        .with_last_event_id("previous")
        .unwrap();
    let mut bytes = &b"id: new\nretry: 17\n"[..];
    assert!(decoder.decode(&mut bytes).unwrap().is_none());
    assert!(bytes.is_empty());
    assert_eq!(decoder.last_event_id(), "previous");
    assert_eq!(decoder.retry_millis(), Some(17));
    assert!(decoder.decode(&mut &b"\n"[..]).unwrap().is_none());
    assert_eq!(decoder.last_event_id(), "new", "an ID-only block commits");
    assert!(decoder
        .decode(&mut &b"id: unfinished\ndata: discarded\n"[..])
        .unwrap()
        .is_none());
    decoder.finish();
    assert_eq!(decoder.last_event_id(), "new");
    assert_eq!(decoder.retry_millis(), Some(17));
    assert_eq!(
        decoder.decode(&mut &b"\n"[..]),
        Err(SseDecodeError::Terminated)
    );

    let mut decoder = SseDecoder::new(SseLimits::default());
    assert!(decoder
        .decode(&mut &b"retry: 999999999999999999999999999999999999999999\nretry:\nretry: -1\n"[..])
        .unwrap()
        .is_none());
    assert_eq!(decoder.retry_millis(), Some(u64::MAX));
    assert_eq!(
        SseDecoder::new(SseLimits::default())
            .with_last_event_id("bad\rid")
            .unwrap_err(),
        SseDecodeError::InvalidLastEventId
    );
    let mut decoder = SseDecoder::new(SseLimits::default());
    assert!(decoder.decode(&mut &b":"[..]).unwrap().is_none());
    assert_eq!(
        decoder.with_last_event_id("too late").unwrap_err(),
        SseDecodeError::AlreadyStarted
    );
}

#[test]
fn decoder_limits_cover_ignored_lines_replacement_expansion_and_aggregate_state() {
    for (wire, limits, kind, limit) in [
        (
            &b":1234\n"[..],
            SseLimits::new().with_max_line_bytes(4),
            SseLimit::Line,
            4,
        ),
        (
            &b"data:\xff\n"[..],
            SseLimits::new().with_max_line_bytes(7),
            SseLimit::Line,
            7,
        ),
        (
            &b"event:x\nid:y\ndata:12345\ndata:\n"[..],
            SseLimits::new().with_max_event_bytes(8),
            SseLimit::Event,
            8,
        ),
    ] {
        let mut decoder = SseDecoder::new(limits);
        assert_eq!(
            decoder.decode(&mut &wire[..]),
            Err(SseDecodeError::LimitExceeded { kind, limit })
        );
        assert!(decoder.is_terminated());
        assert_eq!(decoder.last_event_id(), "");
    }
    assert_eq!(
        SseDecoder::new(SseLimits::new().with_max_event_bytes(2))
            .with_last_event_id("abc")
            .unwrap_err(),
        SseDecodeError::LimitExceeded {
            kind: SseLimit::Event,
            limit: 2,
        }
    );
}

#[derive(Debug, PartialEq, Eq)]
struct SourceError(u32);

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "source error {}", self.0)
    }
}

impl std::error::Error for SourceError {}

#[derive(Default)]
struct Script {
    frames: VecDeque<Result<Frame<BytesCursor>, SourceError>>,
    ended: bool,
    waker: Option<Waker>,
}

struct ScriptBody<'a> {
    script: Rc<RefCell<Script>>,
    polls: &'a Cell<usize>,
    dropped: &'a Cell<bool>,
    _pinned: PhantomPinned,
}

impl Body for ScriptBody<'_> {
    type Data = BytesCursor;
    type Error = SourceError;

    fn poll_frame(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_ref().get_ref();
        this.polls.set(this.polls.get() + 1);
        let mut script = this.script.borrow_mut();
        if let Some(frame) = script.frames.pop_front() {
            return Poll::Ready(Some(frame));
        }
        if script.ended {
            return Poll::Ready(None);
        }
        script.waker = Some(task.waker().clone());
        Poll::Pending
    }
}

impl Drop for ScriptBody<'_> {
    fn drop(&mut self) {
        self.dropped.set(true);
    }
}

fn frame(bytes: &'static [u8]) -> Result<Frame<BytesCursor>, SourceError> {
    Ok(Frame::Data(BytesCursor::new(Bytes::from_static(bytes))))
}

fn script_body<'a>(
    script: &Rc<RefCell<Script>>,
    polls: &'a Cell<usize>,
    dropped: &'a Cell<bool>,
) -> ScriptBody<'a> {
    ScriptBody {
        script: Rc::clone(script),
        polls,
        dropped,
        _pinned: PhantomPinned,
    }
}

fn ready_event<B: Body>(stream: &mut SseStream<B>, task: &mut Context<'_>) -> SseEvent
where
    B::Error: fmt::Debug,
{
    match Pin::new(stream).poll_next(task) {
        Poll::Ready(Some(Ok(event))) => event,
        other => panic!("expected one event, got {other:?}"),
    }
}

fn registrations(cx: &Cx) -> usize {
    cx.inner.read().cancel_waker_registrations.len()
}

#[test]
fn body_retains_one_frame_and_partial_state_across_dropped_next_wait() {
    let cx = Cx::for_testing();
    let script = Rc::new(RefCell::new(Script::default()));
    script
        .borrow_mut()
        .frames
        .push_back(frame(b"id: one\ndata: first\n\ndata: second\n\ndata: part"));
    let polls = Cell::new(0);
    let dropped = Cell::new(false);
    let mut stream = SseStream::new(
        &cx,
        script_body(&script, &polls, &dropped),
        SseLimits::default(),
    );
    let mut task = Context::from_waker(Waker::noop());
    let first = ready_event(&mut stream, &mut task);
    assert_eq!(first.data, "first");
    assert_eq!(first.last_event_id, "one");
    assert_eq!(polls.get(), 1);
    let second = ready_event(&mut stream, &mut task);
    assert_eq!(second.data, "second");
    assert_eq!(second.last_event_id, "one");
    assert_eq!(polls.get(), 1, "the second event remains in the owned frame");

    let mut wait = Box::pin(stream.next_event());
    assert!(wait.as_mut().poll(&mut task).is_pending());
    drop(wait);
    assert!(!dropped.get());
    script.borrow_mut().frames.push_back(frame(b"ial\n\n"));
    let waker = script.borrow_mut().waker.take();
    if let Some(waker) = waker {
        waker.wake();
    }
    let third = ready_event(&mut stream, &mut task);
    assert_eq!(third.data, "partial");
    assert_eq!(third.last_event_id, "one");
    script
        .borrow_mut()
        .frames
        .push_back(frame(b"id: unfinished\ndata: discarded\n"));
    script.borrow_mut().ended = true;
    assert!(matches!(
        Pin::new(&mut stream).poll_next(&mut task),
        Poll::Ready(None)
    ));
    assert!(dropped.get());
    assert_eq!(stream.last_event_id(), "one");
    assert!(stream.is_terminated());
    let final_polls = polls.get();
    assert!(matches!(
        Pin::new(&mut stream).poll_next(&mut task),
        Poll::Ready(None)
    ));
    assert_eq!(polls.get(), final_polls);
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn body_errors_and_oversized_frames_are_terminal_and_drop_the_source() {
    for source_error in [true, false] {
        let cx = Cx::for_testing();
        let script = Rc::new(RefCell::new(Script::default()));
        script.borrow_mut().frames.push_back(if source_error {
            Err(SourceError(71))
        } else {
            frame(b"data: too large\n\n")
        });
        let polls = Cell::new(0);
        let dropped = Cell::new(false);
        let mut stream = SseStream::new(
            &cx,
            script_body(&script, &polls, &dropped),
            SseLimits::new().with_max_frame_bytes(3),
        );
        let mut task = Context::from_waker(Waker::noop());
        match Pin::new(&mut stream).poll_next(&mut task) {
            Poll::Ready(Some(Err(SseStreamError::Source(error)))) if source_error => {
                assert_eq!(error, SourceError(71));
            }
            Poll::Ready(Some(Err(SseStreamError::Decode(error)))) if !source_error => {
                assert_eq!(
                    error,
                    SseDecodeError::LimitExceeded {
                        kind: SseLimit::Frame,
                        limit: 3,
                    }
                );
            }
            other => panic!("unexpected terminal result {other:?}"),
        }
        assert!(dropped.get());
        assert_eq!(polls.get(), 1);
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut task),
            Poll::Ready(None)
        ));
        assert_eq!(polls.get(), 1);
        assert_eq!(registrations(&cx), 0);
    }
}

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
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    (count, waker)
}

#[test]
fn cancelled_parked_body_wakes_and_preserves_reason_without_another_body_poll() {
    let cx = Cx::for_testing();
    let script = Rc::new(RefCell::new(Script::default()));
    let polls = Cell::new(0);
    let dropped = Cell::new(false);
    let mut stream = SseStream::new(
        &cx,
        script_body(&script, &polls, &dropped),
        SseLimits::default(),
    );
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
    assert_eq!(registrations(&cx), 1);
    assert_eq!(polls.get(), 1);
    let expected = CancelReason::user("stop this subscription");
    cx.cancel_with_reason(expected.clone());
    assert!(count.0.load(Ordering::SeqCst) > 0);
    match Pin::new(&mut stream).poll_next(&mut task) {
        Poll::Ready(Some(Err(SseStreamError::Cancelled(reason)))) => {
            assert_eq!(reason, expected);
        }
        other => panic!("expected preserved cancellation, got {other:?}"),
    }
    assert_eq!(polls.get(), 1);
    assert!(dropped.get());
    assert_eq!(registrations(&cx), 0);
}

fn virtual_owner(deadline: Option<Time>) -> (Cx, Arc<VirtualClock>, TimerDriverHandle) {
    let clock = Arc::new(VirtualClock::new());
    let driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let mut budget = Budget::INFINITE;
    budget.deadline = deadline;
    let cx = Cx::new_with_drivers(
        RegionId::new_for_test(0, 1),
        TaskId::new_for_test(0, 0),
        budget,
        None,
        None,
        None,
        Some(driver.clone()),
        None,
    );
    (cx, clock, driver)
}

#[test]
fn owner_deadline_wakes_a_quiet_body_and_masked_expiry_does_not_self_wake() {
    for masked in [false, true] {
        let (cx, clock, driver) = virtual_owner(Some(Time::from_millis(10)));
        let script = Rc::new(RefCell::new(Script::default()));
        let polls = Cell::new(0);
        let dropped = Cell::new(false);
        let mut stream = SseStream::new(
            &cx,
            script_body(&script, &polls, &dropped),
            SseLimits::default(),
        );
        let (count, waker) = counter();
        let mut task = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(driver.next_deadline(), Some(Time::from_millis(10)));
        clock.advance_to(Time::from_millis(10));
        assert_eq!(driver.process_timers(), 1);
        assert!(count.0.load(Ordering::SeqCst) > 0);
        if masked {
            cx.masked(|| {
                count.0.store(0, Ordering::SeqCst);
                for _ in 0..3 {
                    assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
                    assert_eq!(driver.pending_count(), 0);
                    assert_eq!(count.0.load(Ordering::SeqCst), 0);
                    assert!(!dropped.get());
                }
            });
            assert!(count.0.load(Ordering::SeqCst) > 0, "unmask wakes the wait");
        }
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut task),
            Poll::Ready(Some(Err(SseStreamError::Cancelled(reason))))
                if reason.kind == CancelKind::Deadline
        ));
        assert!(driver.is_empty());
        assert!(dropped.get());
        assert_eq!(registrations(&cx), 0);
    }
}

#[test]
fn tightened_owner_budget_replaces_an_existing_or_absent_timer() {
    for initial in [None, Some(Time::from_millis(100))] {
        let (cx, clock, driver) = virtual_owner(initial);
        let script = Rc::new(RefCell::new(Script::default()));
        let polls = Cell::new(0);
        let dropped = Cell::new(false);
        let mut stream = SseStream::new(
            &cx,
            script_body(&script, &polls, &dropped),
            SseLimits::default(),
        );
        let (count, waker) = counter();
        let mut task = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
        assert_eq!(driver.next_deadline(), initial);
        cx.inner.write().budget.deadline = Some(Time::from_millis(10));
        assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(driver.next_deadline(), Some(Time::from_millis(10)));
        clock.advance_to(Time::from_millis(10));
        assert_eq!(driver.process_timers(), 1);
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut task),
            Poll::Ready(Some(Err(SseStreamError::Cancelled(reason))))
                if reason.kind == CancelKind::Deadline
        ));
        assert!(dropped.get());
        assert!(driver.is_empty());
        assert_eq!(registrations(&cx), 0);
    }
}

#[test]
fn endless_comments_and_empty_frames_yield_without_false_eof() {
    let cx = Cx::for_testing();
    let bytes = b": heartbeat\n".repeat(30_000);
    let mut stream = SseStream::new(
        &cx,
        Full::from(bytes),
        SseLimits::default(),
    );
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert!(!stream.is_terminated());
    stream.close();
    assert!(!cx.is_cancel_requested());
    assert_eq!(registrations(&cx), 0);

    let script = Rc::new(RefCell::new(Script::default()));
    for _ in 0..POLL_FRAMES {
        script.borrow_mut().frames.push_back(frame(b""));
    }
    script.borrow_mut().frames.push_back(frame(b"data: after empties\n\n"));
    let polls = Cell::new(0);
    let dropped = Cell::new(false);
    let mut stream = SseStream::new(
        &cx,
        script_body(&script, &polls, &dropped),
        SseLimits::default(),
    );
    count.0.store(0, Ordering::SeqCst);
    assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
    assert_eq!(polls.get(), POLL_FRAMES);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert_eq!(ready_event(&mut stream, &mut task).data, "after empties");
    assert!(!dropped.get());
}

#[test]
fn trailers_do_not_end_the_body_and_later_frames_are_refused() {
    for late_data in [false, true] {
        let cx = Cx::for_testing();
        let script = Rc::new(RefCell::new(Script::default()));
        script.borrow_mut().frames.push_back(Ok(Frame::Trailers(HeaderMap::new())));
        let polls = Cell::new(0);
        let dropped = Cell::new(false);
        let mut stream = SseStream::new(
            &cx,
            script_body(&script, &polls, &dropped),
            SseLimits::default(),
        );
        let mut task = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
        assert!(!dropped.get(), "trailers alone do not prove source EOF");
        script.borrow_mut().frames.push_back(if late_data {
            frame(b"id: bad\ndata: forbidden\n\n")
        } else {
            Ok(Frame::Trailers(HeaderMap::new()))
        });
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut task),
            Poll::Ready(Some(Err(SseStreamError::InvalidFrameOrder)))
        ));
        assert!(dropped.get());
        assert_eq!(stream.last_event_id(), "");
        assert_eq!(registrations(&cx), 0);
    }
}

#[test]
fn invalid_body_chunks_are_refused_before_decoding_or_advance() {
    struct InvalidBuf {
        empty: bool,
        advances: Rc<Cell<usize>>,
    }

    impl Buf for InvalidBuf {
        fn remaining(&self) -> usize {
            1
        }

        fn chunk(&self) -> &[u8] {
            if self.empty { b"" } else { b"data: bypass\n\n" }
        }

        fn advance(&mut self, _count: usize) {
            self.advances.set(self.advances.get() + 1);
            panic!("invalid buffers must never be advanced");
        }
    }

    for empty in [false, true] {
        let cx = Cx::for_testing();
        let advances = Rc::new(Cell::new(0));
        let mut stream = SseStream::new(
            &cx,
            Full::new(InvalidBuf {
                empty,
                advances: Rc::clone(&advances),
            }),
            SseLimits::new().with_max_frame_bytes(1),
        );
        let mut task = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut task),
            Poll::Ready(Some(Err(SseStreamError::InvalidBodyData)))
        ));
        assert_eq!(advances.get(), 0);
        assert_eq!(stream.last_event_id(), "");
        assert!(stream.is_terminated());
        assert_eq!(registrations(&cx), 0);
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut task),
            Poll::Ready(None)
        ));
    }
}

#[test]
fn caught_body_panic_fences_the_stream_and_releases_it_without_repolling() {
    struct PanicBody<'a> {
        polls: &'a Cell<usize>,
        dropped: &'a Cell<bool>,
    }

    impl Body for PanicBody<'_> {
        type Data = BytesCursor;
        type Error = SourceError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _task: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            self.polls.set(self.polls.get() + 1);
            panic!("intentional SSE body poll panic");
        }
    }

    impl Drop for PanicBody<'_> {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    let cx = Cx::for_testing();
    let polls = Cell::new(0);
    let dropped = Cell::new(false);
    let mut stream = SseStream::new(
        &cx,
        PanicBody {
            polls: &polls,
            dropped: &dropped,
        },
        SseLimits::default(),
    );
    let mut task = Context::from_waker(Waker::noop());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = Pin::new(&mut stream).poll_next(&mut task);
    }))
    .is_err());
    assert_eq!(polls.get(), 1);
    assert!(!dropped.get());
    assert!(matches!(
        Pin::new(&mut stream).poll_next(&mut task),
        Poll::Ready(Some(Err(SseStreamError::Poisoned)))
    ));
    assert!(dropped.get());
    assert_eq!(polls.get(), 1);
    assert_eq!(registrations(&cx), 0);
}
