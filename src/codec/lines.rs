//! Codec for newline-delimited text.

use crate::bytes::BytesMut;
use crate::codec::{Decoder, Encoder};
use std::io;

/// Errors produced by `LinesCodec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinesCodecError {
    /// Input exceeded the configured maximum line length.
    MaxLineLengthExceeded,
    /// Input was not valid UTF-8.
    InvalidUtf8,
}

impl std::fmt::Display for LinesCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MaxLineLengthExceeded => write!(f, "line exceeds maximum length"),
            Self::InvalidUtf8 => write!(f, "line is not valid UTF-8"),
        }
    }
}

impl std::error::Error for LinesCodecError {}

impl From<io::Error> for LinesCodecError {
    fn from(_: io::Error) -> Self {
        // Map generic I/O errors to UTF-8 error to avoid leaking io::Error
        // into the line-oriented API.
        Self::InvalidUtf8
    }
}

/// Codec for newline-delimited text.
#[derive(Debug, Clone)]
pub struct LinesCodec {
    max_length: usize,
    next_index: usize,
}

impl LinesCodec {
    /// Creates a new `LinesCodec` with no length limit.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_max_length(usize::MAX)
    }

    /// Creates a new `LinesCodec` with a maximum line length.
    #[must_use]
    pub fn new_with_max_length(max_length: usize) -> Self {
        Self {
            max_length,
            next_index: 0,
        }
    }

    /// Returns the maximum allowed line length.
    #[must_use]
    pub fn max_length(&self) -> usize {
        self.max_length
    }
}

impl Decoder for LinesCodec {
    type Item = String;
    type Error = LinesCodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<String>, Self::Error> {
        let read_to = std::cmp::min(self.max_length.saturating_add(1), src.len());

        let newline_offset = src[self.next_index..read_to]
            .iter()
            .position(|b| *b == b'\n');

        match newline_offset {
            Some(offset) => {
                let newline_index = self.next_index + offset;
                self.next_index = 0;

                let mut line = src.split_to(newline_index + 1);
                // Drop trailing '\n'
                line.truncate(line.len().saturating_sub(1));

                // Handle CRLF
                if line.last() == Some(&b'\r') {
                    line.truncate(line.len().saturating_sub(1));
                }

                let s =
                    String::from_utf8(line.to_vec()).map_err(|_| LinesCodecError::InvalidUtf8)?;
                Ok(Some(s))
            }
            None => {
                if src.len() > self.max_length {
                    return Err(LinesCodecError::MaxLineLengthExceeded);
                }
                self.next_index = read_to;
                Ok(None)
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
    fn test_lines_codec_encode() {
        let mut codec = LinesCodec::new();
        let mut buf = BytesMut::new();

        codec.encode("hello".to_string(), &mut buf).unwrap();
        assert_eq!(&buf[..], b"hello\n");
    }
}
