//! Fuse combinator.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Stream for the [`fuse`](super::StreamExt::fuse) method.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Fuse<S> {
    stream: Option<S>,
}

struct FuseProj<'a, S> {
    stream: Pin<&'a mut Option<S>>,
}

impl<S> Fuse<S> {
    #[allow(unsafe_code)]
    fn project(self: Pin<&mut Self>) -> FuseProj<'_, S> {
        // SAFETY: `stream` is structurally pinned.
        let this = unsafe { self.get_unchecked_mut() };
        FuseProj {
            stream: unsafe { Pin::new_unchecked(&mut this.stream) },
        }
    }

    #[inline]
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream: Some(stream),
        }
    }

    /// Returns a reference to the underlying stream, if it hasn't been fused.
    #[inline]
    pub fn get_ref(&self) -> Option<&S> {
        self.stream.as_ref()
    }

    /// Returns a mutable reference to the underlying stream, if it hasn't been fused.
    #[inline]
    pub fn get_mut(&mut self) -> Option<&mut S> {
        self.stream.as_mut()
    }

    /// Consumes the combinator, returning the underlying stream if it hasn't been fused.
    #[inline]
    pub fn into_inner(self) -> Option<S> {
        self.stream
    }
}

impl<S: Stream> Stream for Fuse<S> {
    type Item = S::Item;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let Some(stream) = this.stream.as_mut().as_pin_mut() else {
            return Poll::Ready(None);
        };

        match stream.poll_next(cx) {
            Poll::Ready(None) => {
                this.stream.set(None);
                Poll::Ready(None)
            }
            other => other,
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.as_ref().map_or((0, Some(0)), Stream::size_hint)
    }
}

#[cfg(test)]
#[path = "fuse_inline_tests.rs"]
mod tests;
