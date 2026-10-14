//! Extension methods for [`AsyncBufRead`].

use crate::io::{AsyncBufRead, Lines, ReadLine, read_line};
use crate::stream::Stream;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Convenience methods for buffered readers such as
/// [`BufReader`](crate::io::BufReader).
///
/// It is exported from [`asupersync::io::ext`](crate::io::ext) only, not the
/// `io` root: `&[u8]` and `Cursor` implement both this trait and
/// `std::io::BufRead`, so a glob import of `asupersync::io` would otherwise
/// make their `lines` / `split` calls ambiguous.
///
/// ```ignore
/// use asupersync::io::BufReader;
/// use asupersync::io::ext::AsyncBufReadExt;
///
/// let mut reader = BufReader::new(stream);
/// let mut header = Vec::new();
/// reader.read_until(b'\0', &mut header).await?;
/// let mut line = String::new();
/// reader.read_line(&mut line).await?;
/// ```
pub trait AsyncBufReadExt: AsyncBufRead {
    /// Returns the buffered bytes, reading more first when the buffer is
    /// empty. An empty slice means end-of-stream. Call [`Self::consume`] for
    /// the bytes used.
    fn fill_buf(&mut self) -> FillBuf<'_, Self>
    where
        Self: Unpin,
    {
        FillBuf { reader: Some(self) }
    }

    /// Marks `amt` buffered bytes as used, so the next read starts after them.
    fn consume(&mut self, amt: usize)
    where
        Self: Unpin,
    {
        AsyncBufRead::consume(Pin::new(self), amt);
    }

    /// Reads into `buf` up to and including the next `byte`, or to
    /// end-of-stream. Returns the number of bytes appended; `0` means
    /// end-of-stream.
    ///
    /// Cancel-safe: bytes already appended stay in `buf`, and a restarted
    /// call continues after them.
    fn read_until<'a>(&'a mut self, byte: u8, buf: &'a mut Vec<u8>) -> ReadUntil<'a, Self>
    where
        Self: Unpin,
    {
        ReadUntil {
            reader: self,
            delimiter: byte,
            buf,
            read: 0,
            max_len: None,
        }
    }

    /// Reads through `byte` without growing `buf.len()` beyond `max_len`.
    ///
    /// The bound includes the delimiter and bytes already in `buf`, so dropping
    /// and restarting a wait does not reset the allowance. Returns only the
    /// number appended by this wait. EOF without a delimiter is still success.
    ///
    /// An initial length above the bound returns `InvalidInput` before polling
    /// the reader. Excess input returns `InvalidData`: the accepted prefix stays
    /// in `buf` and the first byte beyond the allowance is left unconsumed. The
    /// caller must deliberately resume with a larger bound, discard the rest of
    /// the record, or close the reader; the remainder is not a new record.
    ///
    /// This bounds retained bytes, not the vector's capacity, the reader's own
    /// read-ahead, or total stream length. Existing `read_until` stays unbounded.
    fn read_until_limited<'a>(
        &'a mut self,
        byte: u8,
        buf: &'a mut Vec<u8>,
        max_len: usize,
    ) -> ReadUntil<'a, Self>
    where
        Self: Unpin,
    {
        ReadUntil {
            reader: self,
            delimiter: byte,
            buf,
            read: 0,
            max_len: Some(max_len),
        }
    }

    /// Reads one line into `buf`; see [`read_line`].
    fn read_line<'a>(&'a mut self, buf: &'a mut String) -> ReadLine<'a, Self>
    where
        Self: Unpin,
    {
        read_line(self, buf)
    }

    /// The remaining lines, as a [`Stream`] of `String`s without line
    /// endings; see [`Lines::new`], whose line-length cap applies.
    fn lines(self) -> Lines<Self>
    where
        Self: Sized,
    {
        Lines::new(self)
    }

    /// The remaining segments separated by `byte`, as a [`Stream`] of byte
    /// vectors without the separator. Consecutive separators yield empty
    /// segments; a separator at end-of-stream yields no trailing empty one.
    fn split(self, byte: u8) -> Split<Self>
    where
        Self: Sized,
    {
        Split {
            reader: self,
            delimiter: byte,
            segment: Vec::new(),
            finished: false,
            max_segment_bytes: None,
        }
    }

    /// Splits into segments retaining at most `max_segment_bytes` per segment.
    ///
    /// The separator is not part of the bound: zero permits empty segments,
    /// and an exactly full segment can still be followed by a separator or EOF.
    /// The first oversized segment yields one `InvalidData` error and fuses the
    /// stream. No oversized segment is emitted as a successful truncated value.
    /// Use [`Split::into_parts`] to recover the accepted partial segment and the
    /// reader positioned at its first unconsumed continuation byte. Recovery or
    /// draining the rest of that record is the caller's decision.
    ///
    /// Keep the `Split` across dropped borrowing waits to retain its partial
    /// segment. The limit does not bound upstream buffers or allocator capacity.
    fn split_limited(self, byte: u8, max_segment_bytes: usize) -> Split<Self>
    where
        Self: Sized,
    {
        Split {
            reader: self,
            delimiter: byte,
            segment: Vec::new(),
            finished: false,
            max_segment_bytes: Some(max_segment_bytes),
        }
    }
}

impl<R: AsyncBufRead + ?Sized> AsyncBufReadExt for R {}

/// Future for [`AsyncBufReadExt::fill_buf`].
pub struct FillBuf<'a, R: ?Sized> {
    reader: Option<&'a mut R>,
}

impl<'a, R: AsyncBufRead + Unpin + ?Sized> Future for FillBuf<'a, R> {
    type Output = io::Result<&'a [u8]>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let reader = self.reader.take().expect("FillBuf polled after completion");
        // Poll through a reborrow first, so the reader can be kept for the
        // next poll if no data is ready. Once it is, a second fill returns
        // the same buffered bytes, now borrowed for the future's lifetime.
        // End of input is answered directly: a second fill of an empty
        // buffer would start another read, which can be pending after the
        // reader was given up (br-asupersync-68jvck).
        match Pin::new(&mut *reader).poll_fill_buf(cx) {
            Poll::Pending => {
                self.reader = Some(reader);
                Poll::Pending
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok([])) => Poll::Ready(Ok(&[])),
            Poll::Ready(Ok(_)) => Pin::new(reader).poll_fill_buf(cx),
        }
    }
}

/// Future for [`AsyncBufReadExt::read_until`] and its limited variant.
pub struct ReadUntil<'a, R: ?Sized> {
    reader: &'a mut R,
    delimiter: u8,
    buf: &'a mut Vec<u8>,
    read: usize,
    max_len: Option<usize>,
}

impl<R: AsyncBufRead + Unpin + ?Sized> Future for ReadUntil<'_, R> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.max_len.is_some_and(|max| this.buf.len() > max) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "existing buffer exceeds max_len",
            )));
        }
        let mut steps = 0;
        loop {
            // Yield after a bounded number of refills, as ReadLine does, so
            // a source that is always ready cannot hold the worker and a
            // surrounding timeout can fire (br-asupersync-68jvck).
            if steps > 32 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            steps += 1;
            let (used, done) = {
                let available = std::task::ready!(Pin::new(&mut *this.reader).poll_fill_buf(cx))?;
                let offered = this.max_len.map_or(available.len(), |max| {
                    available.len().min(max - this.buf.len())
                });
                if offered == 0 && !available.is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "buffered record exceeds max_len",
                    )));
                }
                // Do not scan or allocate beyond the remaining allowance.
                match memchr::memchr(this.delimiter, &available[..offered]) {
                    Some(index) => {
                        this.buf.extend_from_slice(&available[..=index]);
                        (index + 1, true)
                    }
                    None => {
                        this.buf.extend_from_slice(&available[..offered]);
                        (offered, available.is_empty())
                    }
                }
            };
            AsyncBufRead::consume(Pin::new(&mut *this.reader), used);
            this.read += used;
            if done {
                return Poll::Ready(Ok(std::mem::take(&mut this.read)));
            }
        }
    }
}

/// Stream returned by [`AsyncBufReadExt::split`] and its limited variant.
pub struct Split<R> {
    reader: R,
    delimiter: u8,
    segment: Vec<u8>,
    finished: bool,
    max_segment_bytes: Option<usize>,
}

impl<R> Split<R> {
    /// Returns the reader, with any partly read segment discarded.
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Recovers the reader and any partially consumed segment without losing it.
    ///
    /// The partial bytes precede the unread bytes in the reader. In particular,
    /// after a size error the reader is still inside that same oversized record.
    /// This performs no I/O and does not discard or resynchronize the remainder.
    #[must_use]
    pub fn into_parts(self) -> (R, Vec<u8>) {
        (self.reader, self.segment)
    }
}

impl<R: AsyncBufRead + Unpin> Stream for Split<R> {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        let mut steps = 0;
        loop {
            // Bounded, as in ReadUntil.
            if steps > 32 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            steps += 1;
            let (used, found, oversized) = {
                let available = match Pin::new(&mut this.reader).poll_fill_buf(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Some(Err(error))),
                    Poll::Ready(Ok(available)) => available,
                };
                if available.is_empty() {
                    this.finished = true;
                    if this.segment.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Ok(std::mem::take(&mut this.segment))));
                }
                let remaining = this.max_segment_bytes.map_or(usize::MAX, |max| {
                    max.saturating_sub(this.segment.len())
                });
                // A delimiter immediately after a full segment still fits;
                // inspect that one byte, but never append it to the segment.
                let inspect = available.len().min(remaining.saturating_add(1));
                match memchr::memchr(this.delimiter, &available[..inspect]) {
                    Some(index) => {
                        this.segment.extend_from_slice(&available[..index]);
                        (index + 1, true, false)
                    }
                    None => {
                        let used = available.len().min(remaining);
                        this.segment.extend_from_slice(&available[..used]);
                        (used, false, used < available.len())
                    }
                }
            };
            AsyncBufRead::consume(Pin::new(&mut this.reader), used);
            if oversized {
                this.finished = true;
                return Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "buffered segment exceeds max_segment_bytes",
                ))));
            }
            if found {
                return Poll::Ready(Some(Ok(std::mem::take(&mut this.segment))));
            }
        }
    }
}

impl<R: std::fmt::Debug> std::fmt::Debug for Split<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Split")
            .field("reader", &self.reader)
            .field("delimiter", &self.delimiter)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod limited_tests;
