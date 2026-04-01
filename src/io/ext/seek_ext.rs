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
    use super::*;
    use std::sync::Arc;
    use std::task::{Context, Wake, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
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
}
