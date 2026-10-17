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
#[path = "seek_ext_inline_tests.rs"]
mod tests;
