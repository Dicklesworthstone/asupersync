//! Async seek trait.

use std::io::{self, SeekFrom};
use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Trait for async seeking.
pub trait AsyncSeek {
    /// Attempt to seek to an offset, in bytes, in a stream.
    ///
    /// A seek beyond the end of a stream is allowed, but behavior is defined
    /// by the implementation.
    fn poll_seek(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>>;
}

impl<P: DerefMut + Unpin> AsyncSeek for Pin<P>
where
    P::Target: AsyncSeek,
{
    fn poll_seek(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        self.get_mut().as_mut().poll_seek(cx, pos)
    }
}

impl<S: AsyncSeek + Unpin + ?Sized> AsyncSeek for Box<S> {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        Pin::new(&mut **self).poll_seek(cx, pos)
    }
}

impl<S: AsyncSeek + Unpin + ?Sized> AsyncSeek for &mut S {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        Pin::new(&mut **self).poll_seek(cx, pos)
    }
}

#[cfg(test)]
#[path = "seek_inline_tests.rs"]
mod tests;
