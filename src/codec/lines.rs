//! Codec for newline-delimited text.

use crate::bytes::BytesMut;
use crate::codec::{Decoder, Encoder};
use std::io;

/// Errors produced by `LinesCodec`.
#[derive(Debug)]
pub enum LinesCodecError {
    /// Input exceeded the configured maximum line length.
    MaxLineLengthExceeded,
    /// Input was not valid UTF-8.
    InvalidUtf8,
    /// I/O failed while driving the codec through a framed transport.
    Io(io::Error),
}

impl std::fmt::Display for LinesCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MaxLineLengthExceeded => write!(f, "line exceeds maximum length"),
            Self::InvalidUtf8 => write!(f, "line is not valid UTF-8"),
            Self::Io(err) => write!(f, "i/o error while decoding line: {err}"),
        }
    }
}

impl std::error::Error for LinesCodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::MaxLineLengthExceeded | Self::InvalidUtf8 => None,
        }
    }
}

impl LinesCodecError {
    /// Returns the underlying I/O error kind when this error originated from
    /// the transport instead of the line parser.
    #[inline]
    #[must_use]
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io(err) => Some(err.kind()),
            Self::MaxLineLengthExceeded | Self::InvalidUtf8 => None,
        }
    }
}

impl From<io::Error> for LinesCodecError {
    #[inline]
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Codec for newline-delimited text.
#[derive(Debug, Clone)]
pub struct LinesCodec {
    max_length: usize,
    next_index: usize,
    is_discarding: bool,
}

/// Default maximum line length for [`LinesCodec::new`].
///
/// br-asupersync-4wvgz5: the previous default (`usize::MAX`) made the
/// MaxLineLengthExceeded check effectively unreachable on any real-world
/// memory budget — a peer that streams bytes without a `\n` could drain
/// the host's memory (line-length DoS). 64 KiB is large enough for the
/// vast majority of line-oriented protocols (HTTP/1 status lines, IRC,
/// SMTP, redis text-protocol, log streams) but small enough that an
/// unbounded peer cannot OOM the host. Callers that genuinely need
/// unbounded line lengths must opt in via [`LinesCodec::with_unbounded`].
pub const DEFAULT_MAX_LINE_LENGTH: usize = 64 * 1024;

impl LinesCodec {
    /// Creates a new `LinesCodec` with the default maximum line length
    /// of [`DEFAULT_MAX_LINE_LENGTH`] (64 KiB).
    ///
    /// br-asupersync-4wvgz5: the default is bounded to prevent
    /// line-length DoS. Use [`Self::new_with_max_length`] to set a
    /// custom limit, or [`Self::with_unbounded`] to disable the limit
    /// entirely (only do that when an upstream layer enforces its own
    /// length cap).
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_max_length(DEFAULT_MAX_LINE_LENGTH)
    }

    /// Creates a new `LinesCodec` with no maximum line length.
    ///
    /// br-asupersync-4wvgz5: explicit, grep-able opt-in for callers that
    /// genuinely need unbounded line lengths (e.g. text-streaming
    /// protocols where the application provides its own size guard
    /// upstream). This name is the auditable counterpart to the safe
    /// default in [`Self::new`].
    #[inline]
    #[must_use]
    pub fn with_unbounded() -> Self {
        Self::new_with_max_length(usize::MAX)
    }

    /// Creates a new `LinesCodec` with a maximum line length.
    #[inline]
    #[must_use]
    pub fn new_with_max_length(max_length: usize) -> Self {
        Self {
            max_length,
            next_index: 0,
            is_discarding: false,
        }
    }

    /// Returns the maximum allowed line length.
    #[inline]
    #[must_use]
    pub fn max_length(&self) -> usize {
        self.max_length
    }

    #[inline]
    fn reset_stale_scan_state(&mut self, src: &BytesMut) {
        // Callers may clear or replace the buffer between decode() calls.
        // When the saved scan cursor no longer fits within the current
        // buffer, the prior partial/discard state no longer describes the
        // current bytes, so restart scanning from the new buffer contents.
        if self.next_index > 0 && self.next_index >= src.len() {
            self.next_index = 0;
            self.is_discarding = false;
        }
    }
}

impl Default for LinesCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for LinesCodec {
    type Item = String;
    type Error = LinesCodecError;

    fn max_buffered_frame_len(&self) -> Option<usize> {
        // max_length includes a possible CR, but not the terminating LF.
        // with_unbounded() deliberately has no finite hint, so it does not
        // silently turn off the framed transport's independent memory bound.
        self.max_length.checked_add(1)
    }

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<String>, Self::Error> {
        self.reset_stale_scan_state(src);

        loop {
            let read_to = if self.is_discarding {
                src.len()
            } else {
                std::cmp::min(self.max_length.saturating_add(1), src.len())
            };

            let newline_offset = src[self.next_index..read_to]
                .iter()
                .position(|b| *b == b'\n');

            match (self.is_discarding, newline_offset) {
                (true, Some(offset)) => {
                    // Drop the oversized line, including trailing '\n', and
                    // continue decoding subsequent data.
                    let newline_index = self.next_index + offset;
                    let _ = src.split_to(newline_index + 1);
                    self.next_index = 0;
                    self.is_discarding = false;
                }
                (true, None) => {
                    // Keep memory bounded while discarding an oversized line.
                    src.clear();
                    self.next_index = 0;
                    return Ok(None);
                }
                (false, Some(offset)) => {
                    let newline_index = self.next_index + offset;
                    self.next_index = 0;

                    let mut line = src.split_to(newline_index + 1);
                    // Drop trailing '\n'
                    line.truncate(line.len().saturating_sub(1));

                    // Handle CRLF
                    if line.last() == Some(&b'\r') {
                        line.truncate(line.len().saturating_sub(1));
                    }

                    let s = String::from_utf8(line.to_vec())
                        .map_err(|_| LinesCodecError::InvalidUtf8)?;
                    return Ok(Some(s));
                }
                (false, None) => {
                    if src.len() > self.max_length {
                        self.is_discarding = true;
                        return Err(LinesCodecError::MaxLineLengthExceeded);
                    }
                    self.next_index = read_to;
                    return Ok(None);
                }
            }
        }
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decode(src)? {
            Some(frame) => Ok(Some(frame)),
            None if src.is_empty() => Ok(None),
            None if self.is_discarding => {
                src.clear();
                self.next_index = 0;
                self.is_discarding = false;
                Ok(None)
            }
            None => {
                self.next_index = 0;
                if src.len() > self.max_length {
                    src.clear();
                    return Err(LinesCodecError::MaxLineLengthExceeded);
                }

                let mut line = src.split_to(src.len());
                if line.last() == Some(&b'\r') {
                    line.truncate(line.len().saturating_sub(1));
                }

                let s =
                    String::from_utf8(line.to_vec()).map_err(|_| LinesCodecError::InvalidUtf8)?;
                Ok(Some(s))
            }
        }
    }
}

impl Encoder<String> for LinesCodec {
    type Error = io::Error;

    fn encode(&mut self, line: String, dst: &mut BytesMut) -> Result<(), io::Error> {
        dst.reserve(line.len() + 1);
        dst.put_slice(line.as_bytes());
        dst.put_u8(b'\n');
        Ok(())
    }
}

#[cfg(test)]
#[path = "lines_inline_tests.rs"]
mod tests;
