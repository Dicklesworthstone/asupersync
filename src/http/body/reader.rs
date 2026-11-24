//! Adapts framed HTTP bodies to the native async I/O traits.

use super::{Body, Frame, HeaderMap};
use crate::bytes::Buf;
use crate::io::{AsyncBufRead, AsyncRead, ReadBuf};
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

const MAX_FRAMES_PER_POLL: usize = 32;

/// Reads an HTTP [`Body`] through [`AsyncRead`] and [`AsyncBufRead`].
///
/// The source is pinned once and each DATA buffer is retained until consumed;
/// buffered reads borrow its contiguous bytes without collecting or copying the
/// body. Fragmented [`Buf`] values are supported. Neither the source nor its
/// data needs to be `Unpin`, `Send`, or `'static`.
///
/// Trailers are retained separately and can be inspected with [`Self::trailers`]
/// or removed with [`Self::take_trailers`]. Only the source's actual EOF ends a
/// read: empty DATA frames and trailers do not. DATA after trailers or a second
/// trailers frame is an `InvalidData` error, including after trailers are taken.
///
/// # Cancellation and errors
///
/// Keep this adapter alive across cancelled waits. In particular,
/// [`crate::io::copy_buf`] consumes bytes only after a successful write, so
/// dropping that copy future retains the unwritten suffix here. The source's
/// cancellation and deadline behavior is preserved. Dropping this adapter
/// drops its source, including any owned connection or admission permit.
///
/// EOF or an error releases the source immediately and fuses subsequent reads
/// to EOF. An existing [`io::Error`] keeps its kind and payload; other source
/// errors are retained inside an `Other` error. A caught provider panic fences
/// the adapter: its next read reports `InvalidData` and releases the source
/// without polling it again.
pub struct BodyReader<B: Body> {
    // Retire the transport before buffered user data on ordinary drop.
    body: Option<Pin<Box<B>>>,
    current: Option<B::Data>,
    trailers: Option<HeaderMap>,
    seen_trailers: bool,
    available: usize,
    done: bool,
    poisoned: bool,
}

// Only the Box's allocation is structurally pinned. DATA buffers are never
// exposed through Pin, so moving this wrapper cannot move a pinned source.
impl<B: Body> Unpin for BodyReader<B> {}

impl<B: Body> fmt::Debug for BodyReader<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyReader")
            .field("has_source", &self.body.is_some())
            .field("has_buffer", &self.current.is_some())
            .field("trailers", &self.trailers)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<B: Body> BodyReader<B> {
    /// Pins a source body and creates an initially empty reader.
    #[must_use]
    pub fn new(body: B) -> Self {
        Self {
            body: Some(Box::pin(body)),
            current: None,
            trailers: None,
            seen_trailers: false,
            available: 0,
            done: false,
            poisoned: false,
        }
    }

    /// Returns the source, if it has not been released at EOF or an error.
    #[must_use]
    pub fn get_ref(&self) -> Option<&B> {
        self.body.as_ref().map(|body| body.as_ref().get_ref())
    }

    /// Returns the trailers observed so far.
    ///
    /// Continue reading to EOF to observe errors after the trailers frame.
    #[must_use]
    pub fn trailers(&self) -> Option<&HeaderMap> {
        self.trailers.as_ref()
    }

    /// Takes the observed trailers without relaxing frame-order validation.
    pub fn take_trailers(&mut self) -> Option<HeaderMap> {
        self.trailers.take()
    }

    /// Whether EOF or an error has released the source.
    #[must_use]
    pub fn is_terminated(&self) -> bool {
        self.done
    }

    fn retire(&mut self) {
        self.done = true;
        self.available = 0;
        // Take both before running arbitrary destructors, so an unwind cannot
        // expose a partially retired source for another poll.
        let body = self.body.take();
        let current = self.current.take();
        drop(body);
        drop(current);
    }

    fn invalid(&mut self, message: &'static str) -> Poll<io::Result<()>> {
        self.retire();
        Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, message)))
    }
}

impl<B> BodyReader<B>
where
    B: Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.done {
            return Poll::Ready(Ok(()));
        }
        if self.poisoned {
            return self.invalid("HTTP body reader has unknown effects after a provider panic");
        }

        for _ in 0..MAX_FRAMES_PER_POLL {
            if let Some(data) = self.current.as_ref() {
                self.poisoned = true;
                let remaining = data.remaining();
                let chunk_len = data.chunk().len();
                self.poisoned = false;
                if chunk_len > remaining || (remaining != 0 && chunk_len == 0) {
                    return self.invalid("HTTP body DATA buffer violates its Buf contract");
                }
                if remaining != 0 {
                    return Poll::Ready(Ok(()));
                }
                self.current = None;
            }

            self.poisoned = true;
            let frame = self
                .body
                .as_mut()
                .expect("live body reader owns its source")
                .as_mut()
                .poll_frame(cx);
            self.poisoned = false;
            match frame {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    self.retire();
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(error))) => {
                    self.retire();
                    let error: Box<dyn std::error::Error + Send + Sync> = error.into();
                    return Poll::Ready(Err(match error.downcast::<io::Error>() {
                        Ok(error) => *error,
                        Err(error) => io::Error::other(error),
                    }));
                }
                Poll::Ready(Some(Ok(Frame::Data(data)))) => {
                    if self.seen_trailers {
                        return self.invalid("HTTP body contains DATA after trailers");
                    }
                    self.current = Some(data);
                }
                Poll::Ready(Some(Ok(Frame::Trailers(trailers)))) => {
                    if self.seen_trailers {
                        return self.invalid("HTTP body contains multiple trailers frames");
                    }
                    self.seen_trailers = true;
                    self.trailers = Some(trailers);
                }
            }
        }

        // An indefinitely ready producer of empty frames must yield without
        // reporting a false EOF to copy or framing consumers.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<B> AsyncRead for BodyReader<B>
where
    B: Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let data = std::task::ready!(Pin::new(&mut *this).poll_fill_buf(cx))?;
        let count = data.len().min(buf.remaining());
        buf.put_slice(&data[..count]);
        Pin::new(this).consume(count);
        // Return immediately after progress. A later frame error can never
        // hide bytes already copied into this call's destination.
        Poll::Ready(Ok(()))
    }
}

impl<B> AsyncBufRead for BodyReader<B>
where
    B: Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        std::task::ready!(this.poll_data(cx))?;
        if this.done {
            return Poll::Ready(Ok(&[]));
        }
        this.poisoned = true;
        let data = this.current.as_ref().expect("readable DATA frame").chunk();
        this.available = data.len();
        this.poisoned = false;
        Poll::Ready(Ok(data))
    }

    fn consume(self: Pin<&mut Self>, amount: usize) {
        let this = self.get_mut();
        if this.done || this.poisoned {
            return;
        }
        // Do not let an oversized consume skip a later contiguous chunk or
        // frame. A caller can consume only the bytes it was actually offered.
        let amount = amount.min(this.available);
        if amount == 0 {
            return;
        }
        this.poisoned = true;
        this.current
            .as_mut()
            .expect("offered DATA frame")
            .advance(amount);
        this.available -= amount;
        this.poisoned = false;
    }
}

#[cfg(test)]
#[path = "reader_inline_tests.rs"]
mod tests;
