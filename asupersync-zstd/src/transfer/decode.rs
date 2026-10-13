//! The receiving half of the retained asynchronous transfer engine.

use super::{Transfer, TransferProgress, Transform};
use crate::{DecodeError, DecodeLimits, StreamDecoder, StreamProgress};
use std::future::poll_fn;
use std::io;
use std::task::{Context, Poll};

fn decode_error(error: DecodeError) -> io::Error {
    let kind = match error {
        DecodeError::Truncated => io::ErrorKind::UnexpectedEof,
        DecodeError::DictionaryUnsupported => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error)
}

impl Transform for StreamDecoder {
    fn process(&mut self, input: &[u8], output: &mut [u8]) -> io::Result<StreamProgress> {
        self.decode(input, output).map_err(decode_error)
    }

    fn finish(&mut self, output: &mut [u8]) -> io::Result<StreamProgress> {
        StreamDecoder::finish(self, output).map_err(decode_error)
    }
}

/// A caller-owned asynchronous Zstandard decoding transfer with explicit limits.
///
/// Drives nonblocking source/sink callbacks using the same retained I/O state,
/// backpressure, 32-iteration poll budget and cancellation contract as
/// [`super::EncodeTransfer`]. Dropping a `run` future preserves read-ahead,
/// partially written output and decoder history in this object. Resume with
/// the same source and sink, at their unchanged positions. I/O `Interrupted`
/// errors return immediately and are resumable; other errors are terminal.
/// Cooperative cancellation is supplied by the callbacks, not ambient state.
///
/// The output limit is cumulative across concatenated frames, not reset at
/// each frame. Source EOF must validate with the decoder before sink flush:
/// empty input, partial frames and trailing partial magic are `UnexpectedEof`;
/// corrupt data and exceeded limits are `InvalidData`; dictionaries are
/// `Unsupported`. A valid empty frame succeeds. Skippable frames are bounded
/// and discarded incrementally, according to the supplied policy.
///
/// **Sink bytes are provisional until the transfer succeeds.** A late checksum
/// or truncation error can occur after earlier output has been written. A
/// failure never implies rollback, and a successful sink flush is not fsync
/// or authentication. Stage output and perform application-level integrity
/// checks before publishing it when atomic or authenticated delivery is needed.
/// No tasks, threads, runtime dependencies or I/O authority are created.
/// Completion flushes but does not shut down or drop the caller's sink.
///
/// # Example
///
/// These callbacks use memory-only I/O. For a socket or file, supply its
/// nonblocking poll functions instead of blocking `std::io` calls.
///
/// ```
/// use asupersync_zstd::{DecodeLimits, DecodeTransfer};
/// use std::future::Future;
/// use std::io::{Read, Write};
/// use std::pin::pin;
/// use std::task::{Context, Poll, Waker};
///
/// let mut source: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd, 0x20, 2, 0x11, 0, 0, b'h', b'i'];
/// let mut destination = Vec::new();
/// let mut session = DecodeTransfer::new(DecodeLimits::new(2));
/// {
///     let future = session.run(
///         &mut source, &mut destination,
///         |source, _, out| Poll::Ready(source.read(out)),
///         |sink, _, bytes| Poll::Ready(sink.write(bytes)),
///         |sink, _| Poll::Ready(sink.flush()),
///     );
///     let mut future = pin!(future);
///     let result = future.as_mut().poll(&mut Context::from_waker(Waker::noop()));
///     assert!(matches!(result, Poll::Ready(Ok(_))));
/// }
/// assert_eq!(destination, b"hi");
/// assert!(session.is_finished());
/// assert_eq!(session.progress().bytes_written, 2);
/// ```
#[derive(Debug)]
pub struct DecodeTransfer {
    inner: Transfer<StreamDecoder>,
}

impl DecodeTransfer {
    /// Creates a session with cumulative output and per-frame window limits.
    pub fn new(limits: DecodeLimits) -> Self {
        Self {
            inner: Transfer::new(StreamDecoder::new(limits)),
        }
    }

    /// Bytes read from the encoded source and written to the decoded sink,
    /// including progress before an error or cancelled wait.
    pub fn progress(&self) -> TransferProgress {
        self.inner.progress
    }

    /// Whether EOF validation and the final sink flush succeeded.
    pub fn is_finished(&self) -> bool {
        self.inner.complete
    }

    /// Drives the retained session once; a frame boundary is NOT source EOF.
    /// Callbacks must report byte progress only on `Ready(Ok(n))` and arrange
    /// wake delivery on `Pending`. A source read of zero establishes EOF.
    pub fn poll_transfer<S, D, R, W, F>(
        &mut self,
        cx: &mut Context<'_>,
        source: &mut S,
        destination: &mut D,
        read: &mut R,
        write: &mut W,
        flush: &mut F,
    ) -> Poll<io::Result<TransferProgress>>
    where
        S: ?Sized,
        D: ?Sized,
        R: FnMut(&mut S, &mut Context<'_>, &mut [u8]) -> Poll<io::Result<usize>>,
        W: FnMut(&mut D, &mut Context<'_>, &[u8]) -> Poll<io::Result<usize>>,
        F: FnMut(&mut D, &mut Context<'_>) -> Poll<io::Result<()>>,
    {
        self.inner.poll(cx, source, destination, read, write, flush)
    }

    /// Runs until source EOF is validated and the sink is flushed. Dropping
    /// this borrowing future retains progress for another call on this session.
    pub async fn run<S, D, R, W, F>(
        &mut self,
        source: &mut S,
        destination: &mut D,
        mut read: R,
        mut write: W,
        mut flush: F,
    ) -> io::Result<TransferProgress>
    where
        S: ?Sized,
        D: ?Sized,
        R: FnMut(&mut S, &mut Context<'_>, &mut [u8]) -> Poll<io::Result<usize>>,
        W: FnMut(&mut D, &mut Context<'_>, &[u8]) -> Poll<io::Result<usize>>,
        F: FnMut(&mut D, &mut Context<'_>) -> Poll<io::Result<()>>,
    {
        poll_fn(|cx| self.poll_transfer(cx, source, destination, &mut read, &mut write, &mut flush))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::decode_error;
    use crate::DecodeError;
    use std::io;

    #[test]
    fn error_mapping_keeps_the_decoder_cause() {
        for (cause, kind) in [
            (DecodeError::Truncated, io::ErrorKind::UnexpectedEof),
            (DecodeError::DictionaryUnsupported, io::ErrorKind::Unsupported),
            (DecodeError::ChecksumMismatch, io::ErrorKind::InvalidData),
            (DecodeError::WindowTooLarge, io::ErrorKind::InvalidData),
            (DecodeError::OutputTooLarge, io::ErrorKind::InvalidData),
        ] {
            let error = decode_error(cause);
            assert_eq!(error.kind(), kind);
            assert_eq!(error.get_ref().unwrap().downcast_ref::<DecodeError>(), Some(&cause));
        }
    }
}
