//! Raw bytes pass-through codec.

use crate::bytes::{Bytes, BytesMut};
use crate::codec::{Decoder, Encoder};
use std::io;

/// Codec that passes raw bytes through without framing.
///
/// Decoding yields all available bytes in the buffer. Encoding copies
/// the input bytes directly into the output buffer.
#[derive(Debug, Clone, Copy, Default)]
pub struct BytesCodec;

impl BytesCodec {
    /// Creates a new `BytesCodec`.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Decoder for BytesCodec {
    type Item = BytesMut;
    type Error = io::Error;

    #[inline]
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        if src.is_empty() {
            Ok(None)
        } else {
            let len = src.len();
            Ok(Some(src.split_to(len)))
        }
    }
}

macro_rules! impl_bytes_encoder {
    ($($item:ty),+ $(,)?) => {
        $(
            impl Encoder<$item> for BytesCodec {
                type Error = io::Error;

                #[inline]
                fn encode(&mut self, item: $item, dst: &mut BytesMut) -> Result<(), io::Error> {
                    dst.reserve(item.len());
                    dst.put_slice(&item);
                    Ok(())
                }
            }
        )+
    };
}

impl_bytes_encoder!(Bytes, BytesMut, Vec<u8>);

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
    use crate::codec::FramedWrite;
    use crate::io::AsyncWrite;
    use proptest::prelude::*;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    #[test]
    fn decode_returns_all_bytes() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::from("hello");

        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame[..], b"hello");
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_empty_returns_none() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();

        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn encode_bytes() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let data = Bytes::from_static(b"world");

        codec.encode(data, &mut buf).unwrap();
        assert_eq!(&buf[..], b"world");
    }

    #[test]
    fn encode_bytes_mut() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let data = BytesMut::from("test");

        codec.encode(data, &mut buf).unwrap();
        assert_eq!(&buf[..], b"test");
    }

    #[test]
    fn encode_vec() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();

        codec.encode(vec![1, 2, 3], &mut buf).unwrap();
        assert_eq!(&buf[..], &[1, 2, 3]);
    }

    proptest! {
        #[test]
        fn bytes_codec_metamorphic_segmented_encode_matches_concatenated_payload(
            chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 0..16),
        ) {
            let expected = chunks
                .iter()
                .flat_map(|chunk| chunk.iter().copied())
                .collect::<Vec<_>>();

            let mut segmented_codec = BytesCodec::new();
            let mut segmented = BytesMut::new();
            for chunk in &chunks {
                segmented_codec
                    .encode(chunk.clone(), &mut segmented)
                    .expect("BytesCodec encode should be infallible");
            }

            let mut one_shot_codec = BytesCodec::new();
            let mut one_shot = BytesMut::new();
            one_shot_codec
                .encode(Bytes::copy_from_slice(&expected), &mut one_shot)
                .expect("BytesCodec encode should be infallible");

            prop_assert_eq!(
                segmented.as_ref(),
                one_shot.as_ref(),
                "segmented encodes must have the same wire image as one concatenated encode",
            );

            let decoded = segmented_codec
                .decode(&mut segmented)
                .expect("BytesCodec decode should be infallible");
            if expected.is_empty() {
                prop_assert!(decoded.is_none(), "empty wire image should not yield a frame");
            } else {
                let decoded = decoded.expect("non-empty wire image should decode");
                prop_assert_eq!(
                    decoded.as_ref(),
                    expected.as_slice(),
                    "decoded segmented payload must match concatenated input",
                );
            }
            prop_assert!(segmented.is_empty(), "decode must drain the segmented buffer");
            prop_assert!(
                segmented_codec
                    .decode(&mut segmented)
                    .expect("second decode should be infallible")
                    .is_none(),
                "second decode after a drain should be empty",
            );
        }
    }

    // =========================================================================
    // Wave 45 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn bytes_codec_debug_clone_copy_default() {
        let codec = BytesCodec;
        let dbg = format!("{codec:?}");
        assert_eq!(dbg, "BytesCodec");
        let copied = codec;
        let cloned = codec;
        assert_eq!(format!("{copied:?}"), format!("{cloned:?}"));
    }

    /// MR: arbitrary-binary round-trip (br-asupersync-rsnz1h)
    ///
    /// Property: for ANY &[u8] payload (empty, all-0, all-0xFF, random
    /// binary, embedded NULs, embedded UTF-8 BOM, embedded CRLF), encode
    /// then decode MUST yield byte-equal payload.
    ///
    /// The bytes_codec is a 1:1 byte-passthrough so this property is
    /// trivial today, but any future framing addition (NUL escaping,
    /// length-prefixing, base64 transport encoding) could regress it
    /// silently. This test locks the invariant.
    ///
    /// Catches: silent semantic drift (decode returns DIFFERENT bytes,
    /// not just a panic — fuzz catches panics; metamorphic catches
    /// drift). Drift here propagates to every downstream codec layer.
    #[test]
    fn mr_arbitrary_binary_round_trip() {
        // Curated edge-case payloads that cover the documented danger
        // patterns even without a property-test framework dependency.
        let edge_cases: Vec<Vec<u8>> = vec![
            // Empty.
            vec![],
            // Single byte: every value 0..=255.
            (0u8..=255).map(|b| vec![b]).collect::<Vec<_>>().concat(),
            // All zeros (4 KiB).
            vec![0x00u8; 4096],
            // All 0xFF (4 KiB).
            vec![0xFFu8; 4096],
            // Embedded NULs.
            b"hello\0world\0\0\0".to_vec(),
            // Embedded UTF-8 BOM + CRLF.
            b"\xEF\xBB\xBFheader\r\nbody\r\n".to_vec(),
            // Full byte range as a single 256-byte payload.
            (0u8..=255).collect::<Vec<u8>>(),
            // Non-trivial random-looking binary.
            (0u16..1024)
                .flat_map(|i| {
                    let n = (i.wrapping_mul(0x9E37u16) ^ i) as u8;
                    std::iter::repeat_n(n, ((n % 7) + 1) as usize)
                })
                .collect::<Vec<_>>(),
        ];

        for (i, payload) in edge_cases.iter().enumerate() {
            let mut codec = BytesCodec::new();
            let mut buf = BytesMut::new();
            codec
                .encode(Bytes::copy_from_slice(payload), &mut buf)
                .unwrap_or_else(|e| panic!("encode case {i} failed: {e}"));
            // BytesCodec amplification is identity (no header).
            assert_eq!(
                buf.len(),
                payload.len(),
                "case {i}: BytesCodec must be 1:1 (no framing overhead)"
            );
            let decoded_opt = codec
                .decode(&mut buf)
                .unwrap_or_else(|e| panic!("decode case {i} failed: {e}"));
            let decoded_bytes: Vec<u8> = match decoded_opt {
                Some(b) => b.to_vec(),
                None => {
                    if payload.is_empty() {
                        // Empty input: codec may yield None — also acceptable.
                        Vec::new()
                    } else {
                        panic!("decode case {i} yielded None for non-empty payload")
                    }
                }
            };
            assert_eq!(
                decoded_bytes,
                *payload,
                "case {i}: round-trip drift — payload {} bytes, decoded {} bytes",
                payload.len(),
                decoded_bytes.len()
            );
        }
    }

    /// br-asupersync-279dns: golden snapshot pinning the canonical
    /// encoded byte layout for representative shapes. BytesCodec is
    /// passthrough (length-of-buffer == length-of-encoded), but the
    /// snapshot is the explicit contract: any change to layout
    /// (chunking, framing prefix, padding) requires a deliberate
    /// `cargo insta accept`.
    ///
    /// Encoded output is hex-formatted into a stable string so insta's
    /// inline snapshot is human-readable on review.
    fn hex_dump(b: &[u8]) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            write!(&mut s, "{byte:02x}").expect("infallible write to String");
        }
        s
    }

    #[test]
    fn dns279_encode_bytes_golden_layout() {
        // Representative shapes: empty, single, alignment boundary,
        // CRLF-bearing, all-NUL, all-0xFF, embedded NUL, multi-byte UTF-8.
        let cases: &[(&str, &[u8])] = &[
            ("empty", &[]),
            ("single_a", b"a"),
            ("aligned4_abcd", b"abcd"),
            ("crlf", b"GET / HTTP/1.1\r\n\r\n"),
            ("all_nul_8", &[0u8; 8]),
            ("all_ff_8", &[0xFFu8; 8]),
            ("embedded_nul", b"AB\x00CD"),
            ("utf8_emoji", "Hello 🦀\n".as_bytes()),
        ];

        let mut report = String::new();
        for (name, payload) in cases {
            let mut codec = BytesCodec::new();
            let mut buf = BytesMut::new();
            codec
                .encode(Bytes::copy_from_slice(payload), &mut buf)
                .expect("encode infallible for BytesCodec");
            use std::fmt::Write;
            writeln!(
                &mut report,
                "{name} ({len} bytes): {hex}",
                len = buf.len(),
                hex = hex_dump(&buf)
            )
            .expect("infallible");
        }

        insta::assert_snapshot!("dns279_encode_bytes_golden_layout", report);
    }

    #[test]
    fn dns279_decode_buffer_consumed_golden() {
        // Pin the post-decode buffer state: BytesCodec drains the entire
        // input buffer; the residual MUST be empty after a successful
        // decode. A regression that leaves bytes behind would break
        // framing assumptions for upstream codecs that compose with it.
        let cases: &[(&str, &[u8])] = &[
            ("empty_yields_none", &[]),
            ("nonempty_drains_buffer", b"payload"),
        ];

        let mut report = String::new();
        for (name, payload) in cases {
            let mut codec = BytesCodec::new();
            let mut buf = BytesMut::from(*payload);
            let frame = codec.decode(&mut buf).expect("decode infallible");
            use std::fmt::Write;
            writeln!(
                &mut report,
                "{name}: input_len={input}, frame={frame_state}, residual_len={residual}",
                input = payload.len(),
                frame_state = match &frame {
                    Some(f) => format!("Some({} bytes)", f.len()),
                    None => "None".to_string(),
                },
                residual = buf.len()
            )
            .expect("infallible");
        }

        insta::assert_snapshot!("dns279_decode_buffer_consumed_golden", report);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[derive(Clone, Copy)]
    enum WriteStep {
        Write(usize),
        Pending,
    }

    #[derive(Clone, Copy)]
    enum FlushStep {
        Ready,
        Pending,
    }

    struct ScriptedWriter {
        inner: Vec<u8>,
        write_steps: VecDeque<WriteStep>,
        flush_steps: VecDeque<FlushStep>,
    }

    impl ScriptedWriter {
        fn new(steps: impl IntoIterator<Item = WriteStep>) -> Self {
            Self {
                inner: Vec::new(),
                write_steps: steps.into_iter().collect(),
                flush_steps: VecDeque::new(),
            }
        }

        fn with_flush_steps(
            steps: impl IntoIterator<Item = WriteStep>,
            flush_steps: impl IntoIterator<Item = FlushStep>,
        ) -> Self {
            Self {
                inner: Vec::new(),
                write_steps: steps.into_iter().collect(),
                flush_steps: flush_steps.into_iter().collect(),
            }
        }
    }

    impl AsyncWrite for ScriptedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            match this
                .write_steps
                .pop_front()
                .unwrap_or(WriteStep::Write(buf.len()))
            {
                WriteStep::Pending => Poll::Pending,
                WriteStep::Write(limit) => {
                    let n = limit.min(buf.len());
                    this.inner.extend_from_slice(&buf[..n]);
                    Poll::Ready(Ok(n))
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            match this.flush_steps.pop_front().unwrap_or(FlushStep::Ready) {
                FlushStep::Ready => Poll::Ready(Ok(())),
                FlushStep::Pending => Poll::Pending,
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct TokioUtilBytesCodecWriteRef<W> {
        inner: W,
        encoder: tokio_util::codec::BytesCodec,
        buffer: tokio_util::bytes::BytesMut,
    }

    impl<W> TokioUtilBytesCodecWriteRef<W> {
        fn new(inner: W) -> Self {
            Self {
                inner,
                encoder: tokio_util::codec::BytesCodec::new(),
                buffer: tokio_util::bytes::BytesMut::new(),
            }
        }

        fn get_ref(&self) -> &W {
            &self.inner
        }

        fn write_buffer(&self) -> &[u8] {
            &self.buffer
        }
    }

    impl<W> TokioUtilBytesCodecWriteRef<W>
    where
        W: AsyncWrite + Unpin,
    {
        fn send(&mut self, item: tokio_util::bytes::Bytes) -> Result<(), io::Error> {
            tokio_util::codec::Encoder::encode(&mut self.encoder, item, &mut self.buffer)
        }

        fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            while !self.buffer.is_empty() {
                let n = match Pin::new(&mut self.inner).poll_write(cx, &self.buffer) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(n)) => n,
                };

                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write frame to transport",
                    )));
                }

                let _ = self.buffer.split_to(n);
            }

            Pin::new(&mut self.inner).poll_flush(cx)
        }
    }

    #[test]
    fn conformance_partial_flush_boundary_matches_tokio_util_bytes_codec() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let payload = b"abcdef";

        let mut actual = FramedWrite::new(
            ScriptedWriter::new([WriteStep::Write(3), WriteStep::Pending]),
            BytesCodec::new(),
        );
        let mut reference = TokioUtilBytesCodecWriteRef::new(ScriptedWriter::new([
            WriteStep::Write(3),
            WriteStep::Pending,
        ]));

        actual
            .send(Bytes::copy_from_slice(payload))
            .expect("encode actual payload");
        reference
            .send(tokio_util::bytes::Bytes::copy_from_slice(payload))
            .expect("encode reference payload");

        assert!(
            matches!(actual.poll_flush(&mut cx), Poll::Pending),
            "our framed writer should stop at the partial-flush boundary"
        );
        assert!(
            matches!(reference.poll_flush(&mut cx), Poll::Pending),
            "tokio-util reference should stop at the same partial-flush boundary"
        );

        assert_eq!(actual.get_ref().inner, reference.get_ref().inner);
        assert_eq!(&actual.get_ref().inner, b"abc");
        assert_eq!(&actual.write_buffer()[..], reference.write_buffer());
        assert_eq!(&actual.write_buffer()[..], b"def");

        assert!(
            matches!(actual.poll_flush(&mut cx), Poll::Ready(Ok(()))),
            "our framed writer should drain the buffered suffix on the next flush"
        );
        assert!(
            matches!(reference.poll_flush(&mut cx), Poll::Ready(Ok(()))),
            "tokio-util reference should drain the buffered suffix on the next flush"
        );

        assert!(actual.write_buffer().is_empty());
        assert!(reference.write_buffer().is_empty());
        assert_eq!(actual.get_ref().inner, reference.get_ref().inner);
        assert_eq!(&actual.get_ref().inner, payload);
    }

    #[test]
    fn conformance_transport_flush_pending_after_write_matches_tokio_util_bytes_codec() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let payload = b"abcdef";

        let mut actual = FramedWrite::new(
            ScriptedWriter::with_flush_steps(
                [WriteStep::Write(payload.len())],
                [FlushStep::Pending, FlushStep::Ready],
            ),
            BytesCodec::new(),
        );
        let mut reference = TokioUtilBytesCodecWriteRef::new(ScriptedWriter::with_flush_steps(
            [WriteStep::Write(payload.len())],
            [FlushStep::Pending, FlushStep::Ready],
        ));

        actual
            .send(Bytes::copy_from_slice(payload))
            .expect("encode actual payload");
        reference
            .send(tokio_util::bytes::Bytes::copy_from_slice(payload))
            .expect("encode reference payload");

        assert!(
            matches!(actual.poll_flush(&mut cx), Poll::Pending),
            "our framed writer should propagate inner flush pending after draining bytes"
        );
        assert!(
            matches!(reference.poll_flush(&mut cx), Poll::Pending),
            "tokio-util reference should propagate the same inner flush pending state"
        );

        assert_eq!(actual.get_ref().inner, reference.get_ref().inner);
        assert_eq!(&actual.get_ref().inner, payload);
        assert!(actual.write_buffer().is_empty());
        assert!(reference.write_buffer().is_empty());

        assert!(
            matches!(actual.poll_flush(&mut cx), Poll::Ready(Ok(()))),
            "our framed writer should complete once the inner transport flush becomes ready"
        );
        assert!(
            matches!(reference.poll_flush(&mut cx), Poll::Ready(Ok(()))),
            "tokio-util reference should complete on the same resumed flush"
        );

        assert_eq!(actual.get_ref().inner, reference.get_ref().inner);
        assert_eq!(&actual.get_ref().inner, payload);
        assert!(actual.write_buffer().is_empty());
        assert!(reference.write_buffer().is_empty());
    }
}
