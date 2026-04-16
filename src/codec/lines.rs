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

impl LinesCodec {
    /// Creates a new `LinesCodec` with no length limit.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
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
mod tests {
    use super::*;

    #[test]
    fn test_lines_codec_decode() {
        let mut codec = LinesCodec::new();
        let mut buf = BytesMut::from("hello\nworld\n");

        assert_eq!(codec.decode(&mut buf).unwrap(), Some("hello".to_string()));
        assert_eq!(codec.decode(&mut buf).unwrap(), Some("world".to_string()));
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
    }

    #[test]
    fn test_lines_codec_crlf() {
        let mut codec = LinesCodec::new();
        let mut buf = BytesMut::from("hello\r\n");

        assert_eq!(codec.decode(&mut buf).unwrap(), Some("hello".to_string()));
    }

    #[test]
    fn test_lines_codec_max_length() {
        let mut codec = LinesCodec::new_with_max_length(5);
        let mut buf = BytesMut::from("toolong\n");

        assert!(matches!(
            codec.decode(&mut buf),
            Err(LinesCodecError::MaxLineLengthExceeded)
        ));
    }

    #[test]
    fn test_lines_codec_discards_oversized_and_recovers() {
        let mut codec = LinesCodec::new_with_max_length(5);
        let mut buf = BytesMut::from("toolong");

        assert!(matches!(
            codec.decode(&mut buf),
            Err(LinesCodecError::MaxLineLengthExceeded)
        ));

        // Finish the oversized line, then provide a valid line.
        buf.put_slice(b"\nok\n");

        assert_eq!(codec.decode(&mut buf).unwrap(), Some("ok".to_string()));
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
    }

    #[test]
    fn test_lines_codec_reused_shorter_buffer_after_partial_line() {
        let mut codec = LinesCodec::new();
        let mut buf = BytesMut::from("partial");

        assert_eq!(codec.decode(&mut buf).unwrap(), None);

        buf.clear();
        buf.put_slice(b"ok\n");

        assert_eq!(codec.decode(&mut buf).unwrap(), Some("ok".to_string()));
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
    }

    #[test]
    fn test_lines_codec_reused_shorter_buffer_clears_discarding_state() {
        let mut codec = LinesCodec::new_with_max_length(5);
        let mut buf = BytesMut::from("abc");

        assert_eq!(codec.decode(&mut buf).unwrap(), None);

        buf.put_slice(b"def");
        assert!(matches!(
            codec.decode(&mut buf),
            Err(LinesCodecError::MaxLineLengthExceeded)
        ));

        buf.clear();
        buf.put_slice(b"ok\n");

        assert_eq!(codec.decode(&mut buf).unwrap(), Some("ok".to_string()));
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
    }

    #[test]
    fn test_lines_codec_decode_eof_returns_trailing_line() {
        let mut codec = LinesCodec::new();
        let mut buf = BytesMut::from("tail-without-newline");

        assert_eq!(
            codec.decode_eof(&mut buf).unwrap(),
            Some("tail-without-newline".to_string())
        );
        assert_eq!(codec.decode_eof(&mut buf).unwrap(), None);
    }

    #[test]
    fn test_lines_codec_encode() {
        let mut codec = LinesCodec::new();
        let mut buf = BytesMut::new();

        codec.encode("hello".to_string(), &mut buf).unwrap();
        assert_eq!(&buf[..], b"hello\n");
    }

    // =========================================================================
    // Wave 45 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn lines_codec_error_debug_and_display() {
        let e1 = LinesCodecError::MaxLineLengthExceeded;
        let e2 = LinesCodecError::InvalidUtf8;

        assert!(format!("{e1:?}").contains("MaxLineLengthExceeded"));
        assert!(format!("{e2:?}").contains("InvalidUtf8"));
        assert!(format!("{e1}").contains("maximum length"));
        assert!(format!("{e2}").contains("not valid UTF-8"));

        let err: &dyn std::error::Error = &e1;
        assert!(err.source().is_none());
    }

    #[test]
    fn lines_codec_error_from_io() {
        let io_err = std::io::Error::other("test");
        let codec_err: LinesCodecError = io_err.into();
        assert_eq!(codec_err.io_kind(), Some(io::ErrorKind::Other));
        assert!(format!("{codec_err}").contains("i/o error"));
        assert!(std::error::Error::source(&codec_err).is_some());
    }

    #[test]
    fn lines_codec_debug_clone_default() {
        let codec = LinesCodec::new();
        let dbg = format!("{codec:?}");
        assert!(dbg.contains("LinesCodec"), "{dbg}");
        let cloned = codec.clone();
        assert_eq!(cloned.max_length(), codec.max_length());
        let def = LinesCodec::default();
        assert_eq!(def.max_length(), usize::MAX);
    }
}
