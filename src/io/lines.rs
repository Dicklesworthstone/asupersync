//! Async line iterator.

use super::AsyncBufRead;
use crate::stream::Stream;
use std::io;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Iterator over the lines of an [`AsyncBufRead`].
#[derive(Debug)]
pub struct Lines<R> {
    reader: R,
    buf: Vec<u8>,
    max_length: usize,
    completed: bool,
}

/// Default maximum line length for [`Lines::new`].
///
/// Mirrors the safe default used by [`crate::codec::LinesCodec`]: a peer that
/// never sends `\n` must not be able to grow the iterator's internal buffer
/// without bound.
pub const DEFAULT_MAX_LINE_LENGTH: usize = 64 * 1024;

impl<R> Lines<R> {
    /// Creates a new `Lines` iterator.
    pub fn new(reader: R) -> Self {
        Self::new_with_max_length(reader, DEFAULT_MAX_LINE_LENGTH)
    }

    /// Creates a new `Lines` iterator with no maximum line length.
    ///
    /// Callers that genuinely need unbounded lines must opt in explicitly.
    pub fn with_unbounded(reader: R) -> Self {
        Self::new_with_max_length(reader, usize::MAX)
    }

    /// Creates a new `Lines` iterator with a maximum line length.
    pub fn new_with_max_length(reader: R, max_length: usize) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            max_length,
            completed: false,
        }
    }

    /// Returns the maximum allowed line length.
    pub fn max_length(&self) -> usize {
        self.max_length
    }
}

impl<R: AsyncBufRead + Unpin> Stream for Lines<R> {
    type Item = io::Result<String>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(None);
        }
        let mut steps = 0;

        loop {
            if steps > 32 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            steps += 1;

            // 1. Check if we already have a newline at the end of `this.buf`
            // We know it can only be at the end because of step 4.
            if this.buf.last() == Some(&b'\n') {
                // Remove \n
                this.buf.pop();

                // Handle \r\n
                if this.buf.last() == Some(&b'\r') {
                    this.buf.pop();
                }

                let s = String::from_utf8(mem::take(&mut this.buf))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));

                if s.is_err() {
                    this.completed = true;
                }

                return Poll::Ready(Some(s));
            }

            // 2. Poll the reader
            let available = match Pin::new(&mut this.reader).poll_fill_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    this.completed = true;
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(Ok(buf)) => buf,
            };

            // 3. EOF check
            if available.is_empty() {
                if this.buf.is_empty() {
                    this.completed = true;
                    return Poll::Ready(None);
                }
                let s = String::from_utf8(mem::take(&mut this.buf))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
                this.completed = true;
                return Poll::Ready(Some(s));
            }

            // 4. Scan available for newline
            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                let remaining_allowed = this.max_length.saturating_sub(this.buf.len());
                if pos > remaining_allowed {
                    this.completed = true;
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "line exceeds maximum length",
                    ))));
                }
                this.buf.extend_from_slice(&available[..=pos]);
                Pin::new(&mut this.reader).consume(pos + 1);
                // Loop will catch it in step 1
            } else {
                let remaining_allowed = this.max_length.saturating_sub(this.buf.len());
                if available.len() > remaining_allowed {
                    this.completed = true;
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "line exceeds maximum length",
                    ))));
                }
                this.buf.extend_from_slice(available);
                let len = available.len();
                Pin::new(&mut this.reader).consume(len);
            }
        }
    }
}

#[cfg(test)]
#[path = "lines_inline_tests.rs"]
mod tests;
