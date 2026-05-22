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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use proptest::prelude::*;

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
    fn test_lines_codec_tokio_max_length_boundary_crlf_then_recovers() {
        // Mirrors tokio-util's max_length boundary: with max_length=5, a
        // visible five-byte line followed by CRLF still exceeds the bound
        // because the '\n' sits beyond the max_length+1 scan window.
        let mut codec = LinesCodec::new_with_max_length(5);
        let mut buf = BytesMut::from("hello\r\nok\n");

        assert!(matches!(
            codec.decode(&mut buf),
            Err(LinesCodecError::MaxLineLengthExceeded)
        ));
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

    proptest! {
        #[test]
        fn lines_codec_metamorphic_batched_roundtrip_matches_input_order(
            lines in proptest::collection::vec("[^\\r\\n]{0,64}", 0..32),
        ) {
            let mut encoder = LinesCodec::new();
            let mut buf = BytesMut::new();

            for line in &lines {
                encoder
                    .encode(line.clone(), &mut buf)
                    .expect("encoding newline-free line should not fail");
            }

            let mut decoder = LinesCodec::new();
            let mut decoded = Vec::with_capacity(lines.len());
            while let Some(line) = decoder
                .decode(&mut buf)
                .expect("decoding encoded newline-free line should not fail")
            {
                decoded.push(line);
            }

            prop_assert_eq!(
                decoded.as_slice(),
                lines.as_slice(),
                "batching newline-free lines must preserve order and content",
            );
            prop_assert!(
                buf.is_empty(),
                "successful batched decode must consume the encoded buffer",
            );
            prop_assert_eq!(
                decoder
                    .decode_eof(&mut buf)
                    .expect("EOF after full batch decode should not fail"),
                None,
            );
        }
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
        // br-asupersync-4wvgz5: the default is bounded to prevent
        // line-length DoS. usize::MAX is now opt-in via with_unbounded().
        let def = LinesCodec::default();
        assert_eq!(def.max_length(), DEFAULT_MAX_LINE_LENGTH);
        assert_eq!(LinesCodec::new().max_length(), DEFAULT_MAX_LINE_LENGTH);
        assert_eq!(LinesCodec::with_unbounded().max_length(), usize::MAX);
    }

    /// br-asupersync-4wvgz5: a peer that streams bytes without `\n`
    /// must hit the bounded-default ceiling, not OOM the host.
    #[test]
    fn default_max_length_bounds_unterminated_stream() {
        let mut codec = LinesCodec::new();
        let mut buf = BytesMut::new();
        // Push DEFAULT_MAX_LINE_LENGTH+1 bytes with no newline.
        buf.put_slice(&vec![b'x'; DEFAULT_MAX_LINE_LENGTH + 1]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(LinesCodecError::MaxLineLengthExceeded)
        ));
    }

    // =========================================================================
    // br-asupersync-48nj9v — line-ending decode goldens.
    //
    // The line codec's decoded output is observable on the wire (h1
    // status lines, redis text proto, log streams). These goldens pin
    // the canonical decode behavior across CRLF / bare LF / mixed /
    // bare CR / empty / discard / EOF / invalid UTF-8 — exactly the
    // boundaries where past stream regressions have happened. Any
    // change to line-ending handling forces an explicit
    // `cargo insta review` and a deliberate version note.
    // =========================================================================

    /// Drains the codec via `decode` until it reports `None`, recording
    /// each emitted line (or error) plus the post-drain residual.
    fn drain_decode_trace(codec: &mut LinesCodec, buf: &mut BytesMut) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        loop {
            match codec.decode(buf) {
                Ok(Some(line)) => writeln!(&mut out, "  Ok(Some({line:?}))").unwrap(),
                Ok(None) => {
                    writeln!(&mut out, "  Ok(None)").unwrap();
                    break;
                }
                Err(e) => {
                    writeln!(&mut out, "  Err({e:?})").unwrap();
                    // Errors are recoverable; keep draining to surface the
                    // post-error decode behavior (e.g. discard recovery).
                    if buf.is_empty() {
                        break;
                    }
                }
            }
        }
        out
    }

    fn hex_dump(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            write!(&mut s, "{b:02x}").unwrap();
        }
        s
    }

    #[test]
    fn line_endings_decode_golden() {
        // Pins decode behavior for every canonical line ending the
        // codec must handle on the wire. A change to CR/LF stripping
        // is observable here as a snapshot delta.
        use std::fmt::Write;
        let cases: &[(&str, &[u8])] = &[
            ("lf_three_lines", b"a\nb\nc\n"),
            ("crlf_three_lines", b"a\r\nb\r\nc\r\n"),
            ("mixed_crlf_then_lf", b"a\r\nb\nc\r\n"),
            ("mixed_lf_then_crlf", b"a\nb\r\nc\n"),
            // Bare CR mid-line is NOT a delimiter — it must survive in
            // the decoded string. Only CR immediately before LF is
            // stripped (CRLF normalization).
            ("bare_cr_midline", b"foo\rbar\n"),
            ("multiple_bare_cr_then_lf", b"a\rb\rc\nd\n"),
            // Trailing CR with no following LF: the codec waits for
            // the LF and emits nothing yet.
            ("trailing_cr_no_lf", b"abc\r"),
            ("empty_line_lf", b"\n"),
            ("empty_line_crlf", b"\r\n"),
            ("only_cr_no_lf", b"\r"),
            ("only_lf_then_data", b"\nfoo\n"),
            ("crlf_separates_empty_lines", b"\r\n\r\n\r\n"),
            // CRLF at the buffer's last byte boundary: classic split
            // point that stripped the wrong byte in past h1 regressions.
            ("crlf_split_at_end", b"hello\r\n"),
            ("multibyte_utf8_with_crlf", "héllo\r\nwörld\n".as_bytes()),
        ];

        let mut report = String::new();
        for (name, input) in cases {
            let mut codec = LinesCodec::new();
            let mut buf = BytesMut::from(*input);
            let trace = drain_decode_trace(&mut codec, &mut buf);
            writeln!(
                &mut report,
                "{name}: input={hex} ({len}B)",
                hex = hex_dump(input),
                len = input.len()
            )
            .unwrap();
            report.push_str(&trace);
            writeln!(
                &mut report,
                "  residual_len={}, next_index={}, is_discarding={}",
                buf.len(),
                codec.next_index,
                codec.is_discarding
            )
            .unwrap();
        }

        insta::assert_snapshot!("br_48nj9v_line_endings_decode_golden", report);
    }

    #[test]
    fn line_endings_decode_eof_golden() {
        // Pins decode_eof behavior — i.e. how the codec emits the
        // trailing partial line when the peer closes without a final
        // newline. Trailing CR is also stripped (decode_eof mirrors
        // the CRLF rule even without a delimiter).
        use std::fmt::Write;
        let cases: &[(&str, &[u8])] = &[
            ("eof_no_trailing_newline", b"tail-without-newline"),
            ("eof_trailing_lf_only", b"line\n"),
            ("eof_trailing_crlf", b"line\r\n"),
            // EOF with bare CR: codec strips it (treats trailing CR
            // as a CRLF whose LF the peer never sent).
            ("eof_bare_cr_at_end", b"line\r"),
            ("eof_empty", b""),
            ("eof_only_lf", b"\n"),
            ("eof_only_crlf", b"\r\n"),
            ("eof_only_cr", b"\r"),
            ("eof_two_lines_partial_tail", b"first\nsecond"),
            ("eof_crlf_then_partial", b"first\r\nsecond"),
            // Trailing CR mid-stream must NOT be stripped — only the
            // final byte before EOF gets the CRLF treatment.
            ("eof_bare_cr_midline_then_partial", b"line\rmore"),
        ];

        let mut report = String::new();
        for (name, input) in cases {
            let mut codec = LinesCodec::new();
            let mut buf = BytesMut::from(*input);
            writeln!(
                &mut report,
                "{name}: input={hex} ({len}B)",
                hex = hex_dump(input),
                len = input.len()
            )
            .unwrap();
            // Drain first via decode to surface multi-line cases,
            // then call decode_eof until it reports None.
            loop {
                match codec.decode(&mut buf) {
                    Ok(Some(line)) => {
                        writeln!(&mut report, "  decode: Ok(Some({line:?}))").unwrap()
                    }
                    Ok(None) => break,
                    Err(e) => {
                        writeln!(&mut report, "  decode: Err({e:?})").unwrap();
                        break;
                    }
                }
            }
            match codec.decode_eof(&mut buf) {
                Ok(Some(line)) => {
                    writeln!(&mut report, "  decode_eof: Ok(Some({line:?}))").unwrap()
                }
                Ok(None) => writeln!(&mut report, "  decode_eof: Ok(None)").unwrap(),
                Err(e) => writeln!(&mut report, "  decode_eof: Err({e:?})").unwrap(),
            }
            // A second decode_eof on a drained buffer must be Ok(None)
            // — confirms idempotency at the EOF boundary.
            match codec.decode_eof(&mut buf) {
                Ok(Some(line)) => {
                    writeln!(&mut report, "  decode_eof_again: Ok(Some({line:?}))").unwrap()
                }
                Ok(None) => writeln!(&mut report, "  decode_eof_again: Ok(None)").unwrap(),
                Err(e) => writeln!(&mut report, "  decode_eof_again: Err({e:?})").unwrap(),
            }
            writeln!(&mut report, "  residual_len={}", buf.len()).unwrap();
        }

        insta::assert_snapshot!("br_48nj9v_line_endings_decode_eof_golden", report);
    }

    #[test]
    fn max_length_discard_recovery_golden() {
        // Pins the discard-state transitions that gate the
        // line-length DoS defense. A regression here would either
        // (a) re-emit a discarded line as if it were valid, or
        // (b) wedge the codec in `is_discarding=true` after recovery.
        use std::fmt::Write;
        struct Step<'a> {
            label: &'a str,
            push: &'a [u8],
        }
        let cases: &[(&str, usize, &[Step<'_>])] = &[
            (
                "single_oversized_then_recover",
                5,
                &[
                    Step {
                        label: "push_oversized_no_lf",
                        push: b"toolong",
                    },
                    Step {
                        label: "complete_oversized_then_valid",
                        push: b"\nok\n",
                    },
                ],
            ),
            (
                "oversized_with_crlf_then_recover",
                5,
                &[
                    Step {
                        label: "push_oversized_with_cr",
                        push: b"long-line\r",
                    },
                    Step {
                        label: "deliver_lf_then_valid",
                        push: b"\nok\r\n",
                    },
                ],
            ),
            (
                "two_oversized_back_to_back",
                3,
                &[
                    Step {
                        label: "first_oversized",
                        push: b"abcdef",
                    },
                    Step {
                        label: "complete_first_then_second_oversized",
                        push: b"\nuvwxyz",
                    },
                    Step {
                        label: "complete_second_then_valid",
                        push: b"\nhi\n",
                    },
                ],
            ),
            (
                "oversized_chunked_no_lf",
                4,
                &[
                    // None of these ever contain '\n', so the codec
                    // stays in discard state and clears its scratch
                    // buffer between calls — must not OOM.
                    Step {
                        label: "chunk_a",
                        push: b"AAAAAAAA",
                    },
                    Step {
                        label: "chunk_b",
                        push: b"BBBBBBBB",
                    },
                    Step {
                        label: "finally_lf_then_valid",
                        push: b"\nok\n",
                    },
                ],
            ),
        ];

        let mut report = String::new();
        for (name, max_len, steps) in cases {
            writeln!(&mut report, "{name}: max_length={max_len}").unwrap();
            let mut codec = LinesCodec::new_with_max_length(*max_len);
            let mut buf = BytesMut::new();
            for step in *steps {
                buf.put_slice(step.push);
                writeln!(
                    &mut report,
                    "  step={} push={} ({}B) buf_pre={}B",
                    step.label,
                    hex_dump(step.push),
                    step.push.len(),
                    buf.len()
                )
                .unwrap();
                let trace = drain_decode_trace(&mut codec, &mut buf);
                report.push_str(&trace);
                writeln!(
                    &mut report,
                    "    next_index={} is_discarding={} residual_len={}",
                    codec.next_index,
                    codec.is_discarding,
                    buf.len()
                )
                .unwrap();
            }
        }

        insta::assert_snapshot!("br_48nj9v_max_length_discard_recovery_golden", report);
    }

    #[test]
    fn invalid_utf8_rejection_golden() {
        // Pins the InvalidUtf8 reject path. The exact cut points
        // matter: the codec must reject the offending line and leave
        // the codec in a recoverable state for subsequent valid
        // input. (The current implementation propagates the error
        // and relies on the caller to clear the buffer; this golden
        // freezes that contract.)
        use std::fmt::Write;
        let cases: &[(&str, &[u8])] = &[
            // Lone continuation byte where a leading byte is required.
            ("lone_continuation", b"\x80\n"),
            // Invalid 2-byte: leading 0xC3 not followed by a continuation.
            ("incomplete_2byte", b"\xC3\x28\n"),
            // Truncated 4-byte sequence cut by '\n' before the trailing
            // continuations arrive.
            ("truncated_4byte", b"\xF0\x9F\n"),
            // Valid UTF-8 followed by garbage on the SAME line.
            ("valid_then_garbage", b"hi\xFF\n"),
        ];

        let mut report = String::new();
        for (name, input) in cases {
            let mut codec = LinesCodec::new();
            let mut buf = BytesMut::from(*input);
            writeln!(
                &mut report,
                "{name}: input={hex} ({len}B)",
                hex = hex_dump(input),
                len = input.len()
            )
            .unwrap();
            match codec.decode(&mut buf) {
                Ok(Some(line)) => writeln!(&mut report, "  Ok(Some({line:?}))").unwrap(),
                Ok(None) => writeln!(&mut report, "  Ok(None)").unwrap(),
                Err(e) => writeln!(&mut report, "  Err({e:?})").unwrap(),
            }
            writeln!(
                &mut report,
                "  residual_len={}, next_index={}, is_discarding={}",
                buf.len(),
                codec.next_index,
                codec.is_discarding
            )
            .unwrap();
        }

        insta::assert_snapshot!("br_48nj9v_invalid_utf8_rejection_golden", report);
    }

    #[test]
    fn encode_endings_golden() {
        // Pins the encoded wire form: a single '\n' is always
        // appended, never CRLF. If a caller-supplied string already
        // contains '\r' or '\n', the codec emits it verbatim — a
        // future patch that "helpfully" normalizes embedded CR/LF
        // would break framing for callers that intentionally embed
        // them (e.g. multi-line log payloads on a single frame).
        use std::fmt::Write;
        let cases: &[(&str, &str)] = &[
            ("ascii", "hello"),
            ("empty_string", ""),
            ("contains_cr_only", "a\rb"),
            ("contains_lf_only", "a\nb"),
            ("contains_crlf", "a\r\nb"),
            ("multibyte_utf8", "héllo 🦀"),
        ];

        let mut report = String::new();
        for (name, payload) in cases {
            let mut codec = LinesCodec::new();
            let mut buf = BytesMut::new();
            codec.encode((*payload).to_string(), &mut buf).unwrap();
            writeln!(
                &mut report,
                "{name}: payload_chars={} encoded={} ({}B)",
                payload.chars().count(),
                hex_dump(&buf),
                buf.len()
            )
            .unwrap();
        }

        insta::assert_snapshot!("br_48nj9v_encode_endings_golden", report);
    }

    /// METAMORPHIC PROPERTY: encoding a line and then decoding the
    /// resulting bytes must yield the original line, for any UTF-8
    /// string that does NOT contain newline (`\n`) or carriage
    /// return (`\r`) — those characters are codec delimiters and
    /// would split or strip the line by design.
    ///
    /// Symmetry exploited: `decode ∘ encode = id` on the
    /// newline-free domain. Tests the basic codec round-trip
    /// invariant @ 1000 iterations.
    use proptest::prelude::Strategy as _ProptestStrategyForMetamorphic;
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 1000,
            .. proptest::prelude::ProptestConfig::default()
        })]

        #[test]
        fn metamorphic_lines_codec_round_trip(
            line in proptest::prelude::any::<String>()
                .prop_filter(
                    "line must not contain newline or CR (codec delimiters)",
                    |s| !s.contains('\n') && !s.contains('\r'),
                )
                .prop_filter(
                    "line must fit in default max length",
                    |s| s.len() <= DEFAULT_MAX_LINE_LENGTH,
                )
        ) {
            let mut encoder = LinesCodec::new();
            let mut decoder = LinesCodec::new();
            let mut wire = BytesMut::new();
            encoder.encode(line.clone(), &mut wire).unwrap();
            // Encoded form ends with a single '\n'.
            let decoded = decoder.decode(&mut wire).unwrap();
            proptest::prop_assert_eq!(
                decoded, Some(line.clone()),
                "decode(encode(line)) must equal line"
            );
            // Buffer must be fully consumed.
            proptest::prop_assert!(wire.is_empty(), "encoded buffer must be fully consumed by one decode");
        }
    }
}
