//! AsyncSeek extension methods.

use crate::io::AsyncSeek;
use std::future::Future;
use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Extension trait for `AsyncSeek`.
pub trait AsyncSeekExt: AsyncSeek {
    /// Seek to an offset, in bytes, in a stream.
    fn seek(&mut self, pos: SeekFrom) -> Seek<'_, Self>
    where
        Self: Unpin,
    {
        Seek {
            seeker: self,
            pos,
            completed: false,
        }
    }

    /// Rewind to the beginning of the stream.
    fn rewind(&mut self) -> Seek<'_, Self>
    where
        Self: Unpin,
    {
        self.seek(SeekFrom::Start(0))
    }

    /// Returns the current seek position from the start of the stream.
    fn stream_position(&mut self) -> Seek<'_, Self>
    where
        Self: Unpin,
    {
        self.seek(SeekFrom::Current(0))
    }
}

impl<S: AsyncSeek + ?Sized> AsyncSeekExt for S {}

/// Future for `seek`, `rewind`, and `stream_position`.
pub struct Seek<'a, S: ?Sized> {
    seeker: &'a mut S,
    pos: SeekFrom,
    completed: bool,
}

impl<S> Future for Seek<'_, S>
where
    S: AsyncSeek + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(io::Error::other("Seek future polled after completion")));
        }
        let result = Pin::new(&mut *this.seeker).poll_seek(cx, this.pos);
        if result.is_ready() {
            this.completed = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    use std::task::{Context, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    /// A simple in-memory seekable type.
    struct MemSeeker {
        pos: u64,
        len: u64,
    }

    impl MemSeeker {
        fn new(len: u64) -> Self {
            Self { pos: 0, len }
        }
    }

    impl AsyncSeek for MemSeeker {
        fn poll_seek(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            pos: SeekFrom,
        ) -> Poll<io::Result<u64>> {
            let new_pos = match pos {
                SeekFrom::Start(offset) => offset,
                SeekFrom::End(offset) => {
                    if offset >= 0 {
                        self.len.saturating_add(offset.unsigned_abs())
                    } else {
                        self.len.checked_sub(offset.unsigned_abs()).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "seek before start")
                        })?
                    }
                }
                SeekFrom::Current(offset) => {
                    if offset >= 0 {
                        self.pos.saturating_add(offset.unsigned_abs())
                    } else {
                        self.pos.checked_sub(offset.unsigned_abs()).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "seek before start")
                        })?
                    }
                }
            };
            self.pos = new_pos;
            Poll::Ready(Ok(new_pos))
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum SeekStep {
        Pending,
        Ready(u64),
    }

    #[derive(Debug)]
    struct ScriptedSeeker {
        steps: std::collections::VecDeque<SeekStep>,
        positions: Vec<SeekFrom>,
        polls: usize,
        expected_waker: Waker,
        saw_expected_waker: bool,
    }

    impl ScriptedSeeker {
        fn new(expected_waker: Waker, steps: impl IntoIterator<Item = SeekStep>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                positions: Vec::new(),
                polls: 0,
                expected_waker,
                saw_expected_waker: false,
            }
        }
    }

    impl AsyncSeek for ScriptedSeeker {
        fn poll_seek(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            pos: SeekFrom,
        ) -> Poll<io::Result<u64>> {
            self.polls += 1;
            self.positions.push(pos);
            self.saw_expected_waker = cx.waker().will_wake(&self.expected_waker);
            match self.steps.pop_front().expect("script exhausted") {
                SeekStep::Pending => Poll::Pending,
                SeekStep::Ready(position) => Poll::Ready(Ok(position)),
            }
        }
    }

    #[test]
    fn seek_start() {
        init_test("seek_start");
        let mut seeker = MemSeeker::new(100);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = seeker.seek(SeekFrom::Start(42));
        let result = Pin::new(&mut fut).poll(&mut cx);
        let pos = match result {
            Poll::Ready(Ok(p)) => p,
            other => panic!("unexpected: {other:?}"), // ubs:ignore - test logic
        };
        crate::assert_with_log!(pos == 42, "seek start", 42u64, pos);
        crate::test_complete!("seek_start");
    }

    #[test]
    fn seek_end() {
        init_test("seek_end");
        let mut seeker = MemSeeker::new(100);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = seeker.seek(SeekFrom::End(-10));
        let result = Pin::new(&mut fut).poll(&mut cx);
        let pos = match result {
            Poll::Ready(Ok(p)) => p,
            other => panic!("unexpected: {other:?}"), // ubs:ignore - test logic
        };
        crate::assert_with_log!(pos == 90, "seek end", 90u64, pos);
        crate::test_complete!("seek_end");
    }

    #[test]
    fn seek_before_start_fails_without_moving_position() {
        init_test("seek_before_start_fails_without_moving_position");
        let mut seeker = MemSeeker::new(100);
        seeker.pos = 3;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        {
            let mut fut = seeker.seek(SeekFrom::Current(-4));
            let err = match Pin::new(&mut fut).poll(&mut cx) {
                Poll::Ready(Err(err)) => err,
                other => panic!("expected seek-before-start error, got {other:?}"),
            };
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::InvalidInput,
                "error kind",
                io::ErrorKind::InvalidInput,
                err.kind()
            );
        }
        crate::assert_with_log!(seeker.pos == 3, "position unchanged", 3u64, seeker.pos);
        crate::test_complete!("seek_before_start_fails_without_moving_position");
    }

    #[test]
    fn rewind_goes_to_zero() {
        init_test("rewind_goes_to_zero");
        let mut seeker = MemSeeker::new(100);
        seeker.pos = 50;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = seeker.rewind();
        let result = Pin::new(&mut fut).poll(&mut cx);
        let pos = match result {
            Poll::Ready(Ok(p)) => p,
            other => panic!("unexpected: {other:?}"), // ubs:ignore - test logic
        };
        crate::assert_with_log!(pos == 0, "rewind", 0u64, pos);
        crate::test_complete!("rewind_goes_to_zero");
    }

    #[test]
    fn stream_position_returns_current() {
        init_test("stream_position_returns_current");
        let mut seeker = MemSeeker::new(100);
        seeker.pos = 75;
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = seeker.stream_position();
        let result = Pin::new(&mut fut).poll(&mut cx);
        let pos = match result {
            Poll::Ready(Ok(p)) => p,
            other => panic!("unexpected: {other:?}"), // ubs:ignore - test logic
        };
        crate::assert_with_log!(pos == 75, "stream_position", 75u64, pos);
        crate::test_complete!("stream_position_returns_current");
    }

    #[test]
    fn seek_future_retries_same_position_after_pending() {
        init_test("seek_future_retries_same_position_after_pending");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut seeker =
            ScriptedSeeker::new(waker.clone(), [SeekStep::Pending, SeekStep::Ready(64)]);

        {
            let mut fut = seeker.seek(SeekFrom::Start(64));
            let first = Pin::new(&mut fut).poll(&mut cx);
            crate::assert_with_log!(
                matches!(first, Poll::Pending),
                "first poll pending",
                true,
                matches!(first, Poll::Pending)
            );

            let second = Pin::new(&mut fut).poll(&mut cx);
            let ready = matches!(second, Poll::Ready(Ok(64)));
            crate::assert_with_log!(ready, "second poll ready", true, ready);
        }

        crate::assert_with_log!(seeker.polls == 2, "two inner polls", 2, seeker.polls);
        crate::assert_with_log!(
            seeker.positions == vec![SeekFrom::Start(64), SeekFrom::Start(64)],
            "same position retried",
            vec![SeekFrom::Start(64), SeekFrom::Start(64)],
            seeker.positions.clone()
        );
        crate::assert_with_log!(
            seeker.saw_expected_waker,
            "context forwarded",
            true,
            seeker.saw_expected_waker
        );
        crate::test_complete!("seek_future_retries_same_position_after_pending");
    }

    #[test]
    fn seek_future_is_single_use_after_ready() {
        init_test("seek_future_is_single_use_after_ready");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut seeker = ScriptedSeeker::new(waker.clone(), [SeekStep::Ready(9)]);

        {
            let mut fut = seeker.seek(SeekFrom::Current(4));
            let first = Pin::new(&mut fut).poll(&mut cx);
            let ready = matches!(first, Poll::Ready(Ok(9)));
            crate::assert_with_log!(ready, "first poll ready", true, ready);

            let second = Pin::new(&mut fut).poll(&mut cx);
            let err = match second {
                Poll::Ready(Err(err)) => err,
                other => panic!("expected post-completion error, got {other:?}"),
            };
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::Other,
                "post-completion error kind",
                io::ErrorKind::Other,
                err.kind()
            );
        }

        crate::assert_with_log!(seeker.polls == 1, "one inner poll", 1, seeker.polls);
        crate::assert_with_log!(
            seeker.positions == vec![SeekFrom::Current(4)],
            "position polled once",
            vec![SeekFrom::Current(4)],
            seeker.positions.clone()
        );
        crate::test_complete!("seek_future_is_single_use_after_ready");
    }
}
