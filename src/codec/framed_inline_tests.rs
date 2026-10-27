    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::codec::{LengthDelimitedCodec, LinesCodec, LinesCodecError};
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct TrackWaker(Arc<AtomicBool>);

    use std::task::Wake;
    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn track_waker(flag: Arc<AtomicBool>) -> Waker {
        Waker::from(Arc::new(TrackWaker(flag)))
    }

    struct RecordingLinesCodec {
        inner: LinesCodec,
        decode_lengths: Arc<Mutex<Vec<usize>>>,
    }

    impl RecordingLinesCodec {
        fn new() -> (Self, Arc<Mutex<Vec<usize>>>) {
            let decode_lengths = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    inner: LinesCodec::new(),
                    decode_lengths: Arc::clone(&decode_lengths),
                },
                decode_lengths,
            )
        }
    }

    impl Decoder for RecordingLinesCodec {
        type Item = String;
        type Error = LinesCodecError;

        fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            self.decode_lengths
                .lock()
                .expect("decode-length recorder mutex poisoned")
                .push(src.len());
            self.inner.decode(src)
        }

        fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            self.inner.decode_eof(src)
        }
    }

    struct MultiFrameOnEof {
        next: usize,
    }

    impl Decoder for MultiFrameOnEof {
        type Item = usize;
        type Error = io::Error;

        fn decode(&mut self, _src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            unreachable!("ordinary decode must not run before or between EOF frames")
        }

        fn decode_eof(&mut self, _src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            if self.next == 4 {
                return Ok(None);
            }
            let item = self.next;
            self.next += 1;
            Ok(Some(item))
        }
    }

    struct OneByteDuplex {
        data: Vec<u8>,
        pos: usize,
        pending_between_bytes: bool,
        pending_next: bool,
    }

    impl OneByteDuplex {
        fn new(data: &[u8], pending_between_bytes: bool) -> Self {
            Self {
                data: data.to_vec(),
                pos: 0,
                pending_between_bytes,
                pending_next: false,
            }
        }
    }

    impl AsyncRead for OneByteDuplex {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.pending_between_bytes && this.pending_next {
                this.pending_next = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if this.pos == this.data.len() {
                return Poll::Ready(Ok(()));
            }
            buf.put_slice(&this.data[this.pos..=this.pos]);
            this.pos += 1;
            this.pending_next = this.pending_between_bytes;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for OneByteDuplex {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct GateCodec {
        ready: bool,
    }

    impl Decoder for GateCodec {
        type Item = usize;
        type Error = io::Error;

        fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            if self.ready && !src.is_empty() {
                let len = src.len();
                src.clear();
                Ok(Some(len))
            } else {
                Ok(None)
            }
        }
    }

    impl Encoder<()> for GateCodec {
        type Error = io::Error;

        fn encode(&mut self, _item: (), _dst: &mut BytesMut) -> Result<(), Self::Error> {
            self.ready = true;
            Ok(())
        }
    }

    /// Duplex transport backed by separate read and write buffers.
    #[derive(Debug)]
    struct DuplexBuf {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
    }

    impl DuplexBuf {
        fn new(read_data: &[u8]) -> Self {
            Self {
                read_data: read_data.to_vec(),
                read_pos: 0,
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for DuplexBuf {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let remaining = &this.read_data[this.read_pos..];
            if remaining.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.read_pos += n;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for DuplexBuf {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct GatedWriter {
        writable: Arc<AtomicBool>,
        written: Vec<u8>,
    }

    impl GatedWriter {
        fn new(writable: Arc<AtomicBool>) -> Self {
            Self {
                writable,
                written: Vec::new(),
            }
        }
    }

    impl AsyncWrite for GatedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if !this.writable.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            this.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct AlwaysReadyDuplex {
        reads: usize,
        panic_after: usize,
        written: Vec<u8>,
    }

    impl AlwaysReadyDuplex {
        fn new(panic_after: usize) -> Self {
            Self {
                reads: 0,
                panic_after,
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for AlwaysReadyDuplex {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            assert!(
                this.reads < this.panic_after,
                "transport was polled too many times without yielding"
            );
            this.reads += 1;
            buf.put_slice(b"a");
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for AlwaysReadyDuplex {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct AlwaysReadyPartialWriteDuplex {
        writes: usize,
        panic_after: usize,
        max_per_write: usize,
        written: Vec<u8>,
    }

    impl AlwaysReadyPartialWriteDuplex {
        fn new(max_per_write: usize, panic_after: usize) -> Self {
            Self {
                writes: 0,
                panic_after,
                max_per_write,
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for AlwaysReadyPartialWriteDuplex {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for AlwaysReadyPartialWriteDuplex {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            assert!(
                this.writes < this.panic_after,
                "transport was polled too many times without yielding"
            );
            this.writes += 1;
            let n = std::cmp::min(buf.len(), this.max_per_write);
            this.written.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct ErrorDuplex {
        kind: io::ErrorKind,
    }

    impl ErrorDuplex {
        fn new(kind: io::ErrorKind) -> Self {
            Self { kind }
        }
    }

    impl AsyncRead for ErrorDuplex {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let kind = self.get_mut().kind;
            Poll::Ready(Err(io::Error::new(kind, "framed duplex read error")))
        }
    }

    impl AsyncWrite for ErrorDuplex {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn framed_read_and_write() {
        let transport = DuplexBuf::new(b"incoming\n");
        let mut framed = Framed::new(transport, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Read a frame.
        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "incoming"));

        // Write a frame.
        framed.send("outgoing".to_string()).unwrap();
        let poll = framed.poll_flush(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(()))));

        assert_eq!(&framed.get_ref().written, b"outgoing\n");
    }

    #[test]
    fn framed_multiple_reads() {
        let transport = DuplexBuf::new(b"one\ntwo\nthree\n");
        let mut framed = Framed::new(transport, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "one"));

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "two"));

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "three"));

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(None)));
    }

    #[test]
    fn framed_drains_multiple_frames_from_immediate_eof() {
        let transport = DuplexBuf::new(b"");
        let mut framed = Framed::new(transport, MultiFrameOnEof { next: 0 });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        for expected in 0..4 {
            assert!(matches!(
                Pin::new(&mut framed).poll_next(&mut cx),
                Poll::Ready(Some(Ok(item))) if item == expected
            ));
        }
        assert!(matches!(
            Pin::new(&mut framed).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn framed_does_not_decode_unchanged_fragmented_line() {
        for pending_between_bytes in [true, false] {
            let expected = "x".repeat(MAX_READ_PASSES_PER_POLL * 2 + 5);
            let mut wire = expected.as_bytes().to_vec();
            wire.push(b'\n');
            let transport = OneByteDuplex::new(&wire, pending_between_bytes);
            let (codec, decode_lengths) = RecordingLinesCodec::new();
            let mut framed = Framed::new(transport, codec);
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let mut decoded = None;

            for _ in 0..wire.len().saturating_mul(3).saturating_add(10) {
                match Pin::new(&mut framed).poll_next(&mut cx) {
                    Poll::Pending => {}
                    Poll::Ready(Some(Ok(line))) => {
                        decoded = Some(line);
                        break;
                    }
                    Poll::Ready(Some(Err(error))) => {
                        panic!("fragmented line decode failed: {error}")
                    }
                    Poll::Ready(None) => panic!("fragmented line ended before delimiter"),
                }
            }

            assert_eq!(decoded.as_deref(), Some(expected.as_str()));
            let decode_lengths = decode_lengths
                .lock()
                .expect("decode-length recorder mutex poisoned");
            assert_eq!(decode_lengths.len(), wire.len());
            assert_eq!(decode_lengths.first(), Some(&1));
            assert_eq!(decode_lengths.last(), Some(&wire.len()));
            assert!(
                decode_lengths.windows(2).all(|pair| pair[0] < pair[1]),
                "unchanged buffer was decoded twice: {decode_lengths:?}"
            );
        }
    }

    #[test]
    fn framed_codec_mut_and_send_reenable_buffered_decode() {
        for mutate_via_send in [false, true] {
            let transport = OneByteDuplex::new(b"xy", true);
            let mut framed = Framed::new(transport, GateCodec { ready: false });
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);

            assert!(matches!(
                Pin::new(&mut framed).poll_next(&mut cx),
                Poll::Pending
            ));
            assert_eq!(framed.read_buffer().len(), 1);

            if mutate_via_send {
                framed.send(()).unwrap();
            } else {
                framed.codec_mut().ready = true;
            }

            assert!(matches!(
                Pin::new(&mut framed).poll_next(&mut cx),
                Poll::Ready(Some(Ok(1)))
            ));
        }
    }

    #[test]
    fn framed_decodes_coalesced_frames_at_per_frame_cap() {
        let transport = DuplexBuf::new(b"a\nb\nc\n");
        let mut framed = Framed::new(transport, LinesCodec::new()).with_max_buffer_len(2);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        for expected in ["a", "b", "c"] {
            let poll = Pin::new(&mut framed).poll_next(&mut cx);
            assert!(
                matches!(&poll, Poll::Ready(Some(Ok(line))) if line == expected),
                "expected line {expected:?}, got {poll:?}"
            );
            assert!(framed.read_buffer().len() <= 2);
        }
        assert!(matches!(
            Pin::new(&mut framed).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn framed_exact_cap_eof_frame_reaches_decode_eof() {
        let transport = DuplexBuf::new(b"tail");
        let mut framed = Framed::new(transport, LinesCodec::new()).with_max_buffer_len(4);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref line))) if line == "tail"));
        assert!(matches!(
            Pin::new(&mut framed).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn framed_exact_cap_probe_preserves_io_error() {
        let transport = ErrorDuplex::new(io::ErrorKind::ConnectionReset);
        let mut framed = Framed::new(transport, LinesCodec::new()).with_max_buffer_len(4);
        framed.read_buf.extend_from_slice(b"tail");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(
            poll,
            Poll::Ready(Some(Err(LinesCodecError::Io(ref error))))
                if error.kind() == io::ErrorKind::ConnectionReset
        ));
        assert_eq!(framed.read_buffer(), b"tail".as_slice());
    }

    #[test]
    fn framed_default_max_buffer_len_accommodates_lengthdelimited_header() {
        let transport = DuplexBuf::new(b"");
        let framed = Framed::new(transport, LengthDelimitedCodec::new());
        assert_eq!(
            framed.max_buffer_len(),
            crate::codec::framed_read::DEFAULT_MAX_BUFFER_LEN
        );
        assert_eq!(framed.max_buffer_len(), 8 * 1024 * 1024 + 4);
    }

    fn next_with_bounded_polls<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..64 {
            if let Poll::Ready(item) = Pin::new(&mut *stream).poll_next(&mut cx) {
                return item;
            }
        }
        panic!("ready transport did not produce its frame within the poll budget");
    }

    #[test]
    fn framed_accepts_eight_byte_prefix_and_reconfigured_large_frames() {
        for payload_len in [8 * 1024 * 1024, 9 * 1024 * 1024] {
            let mut wire = (payload_len as u64).to_be_bytes().to_vec();
            wire.resize(8 + payload_len, b'z');
            wire.extend_from_slice(&2_u64.to_be_bytes());
            wire.extend_from_slice(b"ok");
            let transport = DuplexBuf {
                read_data: wire,
                read_pos: 0,
                written: Vec::new(),
            };
            let mut framed = Framed::new(transport, LengthDelimitedCodec::new());
            *framed.codec_mut() = LengthDelimitedCodec::builder()
                .length_field_length(8)
                .max_frame_length(payload_len)
                .new_codec();
            assert_eq!(framed.effective_max_buffer_len(), payload_len + 8);

            let frame = next_with_bounded_polls(&mut framed).unwrap().unwrap();
            assert_eq!(frame.len(), payload_len);
            assert!(frame.iter().all(|byte| *byte == b'z'));
            let next = next_with_bounded_polls(&mut framed).unwrap().unwrap();
            assert_eq!(&next[..], b"ok");
            assert!(next_with_bounded_polls(&mut framed).is_none());
        }
    }

    #[test]
    fn framed_explicit_limit_overrides_hint_and_zero_still_disables_limit() {
        let wire = vec![b'x'; 128];
        for limit in [0, 64] {
            let mut framed = Framed::new(DuplexBuf::new(&wire), LinesCodec::new())
                .with_max_buffer_len(limit);
            *framed.codec_mut() = LinesCodec::new_with_max_length(16 * 1024 * 1024);
            assert_eq!(framed.effective_max_buffer_len(), limit);
            let result = next_with_bounded_polls(&mut framed).unwrap();
            if limit == 0 {
                assert_eq!(result.unwrap().as_bytes(), wire.as_slice());
            } else {
                assert_eq!(
                    result.unwrap_err().io_kind(),
                    Some(io::ErrorKind::InvalidData)
                );
                assert_eq!(framed.read_buffer().len(), limit);
            }
            assert!(next_with_bounded_polls(&mut framed).is_none());
        }
    }

    #[test]
    fn framed_unknown_and_unrepresentable_hints_keep_default_limit() {
        let default_limit = crate::codec::framed_read::DEFAULT_MAX_BUFFER_LEN;
        let foreign = Framed::new(DuplexBuf::new(b""), GateCodec { ready: false });
        assert_eq!(foreign.codec().max_buffered_frame_len(), None);
        assert_eq!(foreign.effective_max_buffer_len(), default_limit);
        let unbounded = Framed::new(DuplexBuf::new(b""), LinesCodec::with_unbounded());
        assert_eq!(unbounded.effective_max_buffer_len(), default_limit);
        let invalid_geometry = LengthDelimitedCodec::builder()
            .num_skip(usize::MAX)
            .new_codec();
        let framed = Framed::new(DuplexBuf::new(b""), invalid_geometry);
        assert_eq!(framed.effective_max_buffer_len(), default_limit);
    }

    #[test]
    fn framed_rejects_buffer_growth_past_max_buffer_len_then_poisons() {
        // br-asupersync-bj427s + br-asupersync-3asq77: 256 bytes of 'A' with
        // no newline → LinesCodec never frames, so without the cap the buffer
        // grows unbounded. Cap at 64 → retain the cap, then a one-byte probe
        // trips InvalidData; the read half is poisoned so a re-poll returns
        // None instead of re-emitting the same error forever.
        let payload: Vec<u8> = vec![b'A'; 256];
        let transport = DuplexBuf::new(&payload);
        let mut framed = Framed::new(transport, LinesCodec::new()).with_max_buffer_len(64);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        match poll {
            Poll::Ready(Some(Err(LinesCodecError::Io(err)))) => {
                assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                let msg = format!("{err}");
                assert!(
                    msg.contains("max_buffer_len"),
                    "error must reference max_buffer_len, got: {msg}"
                );
            }
            other => panic!("expected InvalidData from max_buffer_len, got {other:?}"),
        }
        // The probe byte is never appended, so retained memory stops exactly
        // at the configured cap.
        assert_eq!(framed.read_buffer().len(), 64);
        // Poisoned: subsequent polls return None, not a re-emitted error.
        let next = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(
            matches!(next, Poll::Ready(None)),
            "poll after a poisoning error must return None, got {next:?}"
        );
    }

    #[test]
    fn framed_close() {
        let transport = DuplexBuf::new(b"");
        let mut framed = Framed::new(transport, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        framed.send("final".to_string()).unwrap();
        let poll = framed.poll_close(&mut cx);
        assert!(matches!(poll, Poll::Ready(Ok(()))));

        assert_eq!(&framed.get_ref().written, b"final\n");
    }

    #[test]
    fn framed_accessors() {
        let transport = DuplexBuf::new(b"");
        let mut framed = Framed::new(transport, LinesCodec::new());

        assert!(framed.read_buffer().is_empty());
        assert!(framed.write_buffer().is_empty());
        assert_eq!(
            framed.backpressure_boundary(),
            DEFAULT_BACKPRESSURE_BOUNDARY
        );
        let _codec = framed.codec();
        let _codec_mut = framed.codec_mut();
        let _transport = framed.get_ref();
        let _transport_mut = framed.get_mut();
    }

    #[test]
    fn framed_into_parts() {
        let transport = DuplexBuf::new(b"");
        let framed = Framed::new(transport, LinesCodec::new());

        let parts = framed.into_parts();
        assert!(parts.read_buf.is_empty());
        assert!(parts.write_buf.is_empty());
    }

    #[test]
    fn framed_readiness_bounds_pending_buffer_and_recovers() {
        let writable = Arc::new(AtomicBool::new(false));
        let mut framed = Framed::new(GatedWriter::new(Arc::clone(&writable)), LinesCodec::new())
            .with_backpressure_boundary(8);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(framed.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        framed.start_send("abc".to_string()).unwrap();
        assert!(matches!(framed.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        framed.start_send("def".to_string()).unwrap();
        assert_eq!(framed.write_buffer().len(), 8);

        assert!(matches!(framed.poll_ready(&mut cx), Poll::Pending));
        assert_eq!(
            framed.write_buffer().len(),
            8,
            "pending readiness must not grow the buffered prefix"
        );
        assert!(matches!(framed.poll_ready(&mut cx), Poll::Pending));
        assert_eq!(framed.write_buffer().len(), 8);

        writable.store(true, Ordering::SeqCst);
        assert!(matches!(framed.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert!(framed.write_buffer().is_empty());
        assert_eq!(&framed.get_ref().written, b"abc\ndef\n");
    }

    #[test]
    fn framed_boundary_is_soft_for_one_oversized_frame() {
        let writable = Arc::new(AtomicBool::new(false));
        let mut framed = Framed::new(GatedWriter::new(Arc::clone(&writable)), LinesCodec::new())
            .with_backpressure_boundary(4);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(framed.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        framed.start_send("oversized".to_string()).unwrap();
        let oversized_len = framed.write_buffer().len();
        assert!(oversized_len > framed.backpressure_boundary());
        assert!(matches!(framed.poll_ready(&mut cx), Poll::Pending));
        assert_eq!(framed.write_buffer().len(), oversized_len);

        writable.store(true, Ordering::SeqCst);
        assert!(matches!(framed.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert!(framed.write_buffer().is_empty());
    }

    // Pure data-type tests (wave 15 – CyanBarn)

    #[test]
    fn framed_debug() {
        let transport = DuplexBuf::new(b"");
        let framed = Framed::new(transport, LinesCodec::new());
        let dbg = format!("{framed:?}");
        assert!(dbg.contains("Framed"));
        assert!(dbg.contains("read_buf_len"));
        assert!(dbg.contains("write_buf_len"));
    }

    #[test]
    fn framed_with_capacity() {
        let transport = DuplexBuf::new(b"");
        let framed = Framed::with_capacity(transport, LinesCodec::new(), 256);
        // Buffers should have been allocated with the specified capacity.
        assert!(framed.read_buffer().is_empty());
        assert!(framed.write_buffer().is_empty());
        assert_eq!(framed.backpressure_boundary(), 256);
    }

    #[test]
    fn framed_into_inner() {
        let transport = DuplexBuf::new(b"test-data");
        let framed = Framed::new(transport, LinesCodec::new());
        let inner = framed.into_inner();
        assert_eq!(&inner.read_data, b"test-data");
        assert_eq!(inner.read_pos, 0);
    }

    #[test]
    fn framed_parts_fields() {
        let transport = DuplexBuf::new(b"parts-test\n");
        let mut framed = Framed::new(transport, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Read to populate the read buffer then extract parts.
        let _ = Pin::new(&mut framed).poll_next(&mut cx);
        let parts = framed.into_parts();
        // The inner transport and codec should be accessible.
        let inner = parts.inner;
        assert_eq!(&inner.read_data, b"parts-test\n");
        let _ = parts.codec;
    }

    #[test]
    fn framed_get_mut_modifies_transport() {
        let transport = DuplexBuf::new(b"");
        let mut framed = Framed::new(transport, LinesCodec::new());
        framed.get_mut().read_data = b"modified\n".to_vec();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(Some(Ok(ref s))) if s == "modified"));
    }

    #[test]
    fn framed_codec_mut_accessible() {
        let transport = DuplexBuf::new(b"");
        let mut framed = Framed::new(transport, LinesCodec::new());
        // Just verify codec_mut returns a mutable reference.
        let _codec = framed.codec_mut();
    }

    #[test]
    fn framed_empty_read_returns_none() {
        let transport = DuplexBuf::new(b"");
        let mut framed = Framed::new(transport, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Ready(None)));
    }

    #[test]
    fn framed_yields_cooperatively_on_always_ready_transport() {
        let transport = AlwaysReadyDuplex::new(MAX_READ_PASSES_PER_POLL + 1);
        let mut framed = Framed::new(transport, LinesCodec::new());
        let woke = Arc::new(AtomicBool::new(false));
        let waker = track_waker(Arc::clone(&woke));
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        assert!(matches!(poll, Poll::Pending));
        assert!(
            woke.load(Ordering::SeqCst),
            "cooperative yield should self-wake for continued draining"
        );
        assert_eq!(
            framed.get_ref().reads,
            MAX_READ_PASSES_PER_POLL,
            "poll_next should stop after the cooperative read budget"
        );
        assert_eq!(
            framed.read_buffer().len(),
            MAX_READ_PASSES_PER_POLL,
            "already-read bytes must stay buffered across the cooperative yield"
        );
    }

    #[test]
    fn framed_write_side_yields_cooperatively_on_always_ready_partial_transport() {
        let transport = AlwaysReadyPartialWriteDuplex::new(1, MAX_WRITE_PASSES_PER_POLL + 1);
        let mut framed = Framed::new(transport, LinesCodec::new());
        let woke = Arc::new(AtomicBool::new(false));
        let waker = track_waker(Arc::clone(&woke));
        let mut cx = Context::from_waker(&waker);

        framed
            .send("x".repeat(MAX_WRITE_PASSES_PER_POLL + 8))
            .expect("encode test frame");

        let poll = framed.poll_flush(&mut cx);
        assert!(matches!(poll, Poll::Pending));
        assert!(
            woke.load(Ordering::SeqCst),
            "cooperative yield should self-wake for continued draining"
        );
        assert_eq!(
            framed.get_ref().writes,
            MAX_WRITE_PASSES_PER_POLL,
            "poll_flush should stop after the cooperative write budget"
        );
        assert!(
            !framed.write_buffer().is_empty(),
            "buffered frame bytes must remain after the cooperative yield"
        );
    }

    #[test]
    fn framed_preserves_io_error_kind_from_lines_codec() {
        let transport = ErrorDuplex::new(io::ErrorKind::ConnectionReset);
        let mut framed = Framed::new(transport, LinesCodec::new());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let poll = Pin::new(&mut framed).poll_next(&mut cx);
        match poll {
            Poll::Ready(Some(Err(LinesCodecError::Io(err)))) => {
                assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
            }
            other => panic!("expected io error propagation, got {other:?}"), // ubs:ignore - test logic
        }
    }

    /// METAMORPHIC PROPERTY: encoding a list of frames individually
    /// and concatenating them into one wire, then running the wire
    /// through one decoder, must yield the same list — in order, with
    /// the wire fully consumed. Symmetry exploited:
    ///   `decode_each(concat(encode_each(items))) == items`
    /// Each encoder output is self-delimited, so concatenation is
    /// associative w.r.t. decoding; this is the framed-codec analogue
    /// of "encode is the inverse of decode batchwise".
    /// Tests at 1000 iterations.
    use proptest::prelude::Strategy as _ProptestStrategyForMetamorphic;
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 1000,
            .. proptest::prelude::ProptestConfig::default()
        })]

        #[test]
        fn metamorphic_framed_concat_decode_commutes(
            // Each line: ASCII printable, no \n / \r (codec delimiters),
            // bounded length to fit default max.
            lines in proptest::collection::vec(
                proptest::collection::vec(32u8..127, 0..200)
                    .prop_map(|bytes| String::from_utf8(bytes).unwrap()),
                0..32,
            )
        ) {
            // Encode each line individually into a single concatenated wire.
            let mut encoder = LinesCodec::new();
            let mut wire = BytesMut::new();
            for line in &lines {
                encoder.encode(line.clone(), &mut wire).unwrap();
            }

            // Decode all lines from the concatenated wire.
            let mut decoder = LinesCodec::new();
            let mut decoded: Vec<String> = Vec::with_capacity(lines.len());
            while let Some(line) = decoder.decode(&mut wire).unwrap() {
                decoded.push(line);
            }

            proptest::prop_assert_eq!(
                &decoded, &lines,
                "decode_each(concat(encode_each(items))) must equal items"
            );
            proptest::prop_assert!(
                wire.is_empty(),
                "wire must be fully consumed after decoding all encoded lines"
            );
        }
    }
