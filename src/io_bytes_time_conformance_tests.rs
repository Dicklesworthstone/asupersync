//! [br-conformance-18] IO, bytes, and time hot path conformance tests.
//!
//! These tests are intentionally small but production-seam oriented: they use
//! the crate's async IO traits/adapters, zero-copy buffer types, and timer
//! primitives directly instead of local conformance models.

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value
    )]

    use crate::bytes::{Buf, BufMut, Bytes, BytesMut};
    use crate::io::{AsyncRead, AsyncReadExt, BufReader, ReadBuf, copy, read_line};
    use crate::time::{CoalescingConfig, TimeoutFuture, TimerWheel, TimerWheelConfig};
    use crate::types::Time;
    use futures_lite::future;
    use std::future::{pending, ready};
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    struct WakeCounter {
        count: Arc<AtomicUsize>,
    }

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker(count: Arc<AtomicUsize>) -> Waker {
        Waker::from(Arc::new(WakeCounter { count }))
    }

    fn with_task_context<T>(f: impl FnOnce(&mut Context<'_>) -> T) -> T {
        let count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(count);
        let mut cx = Context::from_waker(&waker);
        f(&mut cx)
    }

    fn poll_read_once<R>(reader: &mut R, read_buf: &mut ReadBuf<'_>) -> io::Result<()>
    where
        R: AsyncRead + Unpin,
    {
        with_task_context(|cx| match Pin::new(reader).poll_read(cx, read_buf) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("in-memory AsyncRead seam should not park"),
        })
    }

    fn wake_all(wakers: impl IntoIterator<Item = Waker>) {
        for waker in wakers {
            waker.wake_by_ref();
        }
    }

    #[test]
    fn async_read_and_copy_preserve_exact_bytes() {
        let cases: [&[u8]; 4] = [
            b"",
            b"x",
            b"hello asupersync io",
            b"chunk-0\0chunk-1\nchunk-2\xff",
        ];

        for input in cases {
            let mut reader = std::io::Cursor::new(input.to_vec());
            let mut collected = Vec::new();
            let read = future::block_on(reader.read_to_end(&mut collected))
                .expect("read_to_end over Cursor must complete");
            assert_eq!(read, input.len(), "read_to_end byte count drifted");
            assert_eq!(collected, input, "read_to_end changed payload bytes");

            let mut copy_reader: &[u8] = input;
            let mut copied = Vec::new();
            let written = future::block_on(copy(&mut copy_reader, &mut copied))
                .expect("copy over in-memory AsyncRead/AsyncWrite must complete");
            assert_eq!(written as usize, input.len(), "copy byte count drifted");
            assert_eq!(copied, input, "copy changed payload bytes");
            assert!(copy_reader.is_empty(), "copy must drain the reader");
        }
    }

    #[test]
    fn read_buf_filled_region_tracks_direct_async_read_progress() {
        let mut reader: &[u8] = b"abcdef";
        let mut storage = [0u8; 4];
        let mut read_buf = ReadBuf::new(&mut storage);

        poll_read_once(&mut reader, &mut read_buf).expect("slice AsyncRead should complete");
        assert_eq!(read_buf.filled(), b"abcd");
        assert_eq!(read_buf.remaining(), 0);
        assert_eq!(reader, b"ef");

        let mut tail_storage = [0u8; 8];
        let mut tail_buf = ReadBuf::new(&mut tail_storage);
        poll_read_once(&mut reader, &mut tail_buf).expect("slice AsyncRead should complete");
        assert_eq!(tail_buf.filled(), b"ef");
        assert_eq!(tail_buf.remaining(), 6);
        assert!(reader.is_empty());
    }

    #[test]
    fn read_line_uses_production_buffering_and_crlf_normalization() {
        let bytes: &[u8] = b"alpha\nbeta\r\ngamma";
        let mut reader = BufReader::with_capacity(3, bytes);

        let mut line = String::new();
        let n =
            future::block_on(read_line(&mut reader, &mut line)).expect("first line should decode");
        assert_eq!(n, 6);
        assert_eq!(line, "alpha\n");

        line.clear();
        let n =
            future::block_on(read_line(&mut reader, &mut line)).expect("second line should decode");
        assert_eq!(n, 6, "byte count includes the stripped carriage return");
        assert_eq!(line, "beta\n");

        line.clear();
        let n = future::block_on(read_line(&mut reader, &mut line))
            .expect("unterminated final line should decode");
        assert_eq!(n, 5);
        assert_eq!(line, "gamma");

        line.clear();
        let n = future::block_on(read_line(&mut reader, &mut line))
            .expect("EOF should return zero bytes");
        assert_eq!(n, 0);
        assert!(line.is_empty());
    }

    #[test]
    fn bytes_split_and_freeze_preserve_identity() {
        let original = b"frame-prefix|frame-body|frame-tail";
        let split_points = [0, 1, 12, original.len() - 1, original.len()];

        for split_at in split_points {
            let mut bytes = Bytes::copy_from_slice(original);
            let suffix = bytes.split_off(split_at);
            assert_eq!(&bytes[..], &original[..split_at]);
            assert_eq!(&suffix[..], &original[split_at..]);

            let mut reconstructed = Vec::new();
            reconstructed.extend_from_slice(&bytes);
            reconstructed.extend_from_slice(&suffix);
            assert_eq!(reconstructed, original, "Bytes::split_off broke identity");

            let mut bytes = Bytes::copy_from_slice(original);
            let prefix = bytes.split_to(split_at);
            assert_eq!(&prefix[..], &original[..split_at]);
            assert_eq!(&bytes[..], &original[split_at..]);

            let mut reconstructed = Vec::new();
            reconstructed.extend_from_slice(&prefix);
            reconstructed.extend_from_slice(&bytes);
            assert_eq!(reconstructed, original, "Bytes::split_to broke identity");
        }

        let mut mutable = BytesMut::with_capacity(original.len() + 16);
        mutable.put_slice(&original[..12]);
        mutable.extend_from_slice(&original[12..]);
        assert_eq!(&mutable[..], original);

        let prefix = mutable.split_to(12);
        assert_eq!(&prefix[..], &original[..12]);
        assert_eq!(&mutable[..], &original[12..]);

        let suffix = mutable.split_off(mutable.len() - 4);
        assert_eq!(&mutable[..], &original[12..original.len() - 4]);
        assert_eq!(&suffix[..], &original[original.len() - 4..]);

        let frozen = BytesMut::from(&original[..]).freeze();
        assert_eq!(&frozen[..], original, "BytesMut::freeze changed bytes");

        let owned = BytesMut::from(&original[..]).into_vec();
        assert_eq!(owned, original, "BytesMut::into_vec changed bytes");
    }

    #[test]
    fn bytes_buf_and_bufmut_round_trip_wire_values() {
        let mut wire = Vec::new();
        BufMut::put_u16(&mut wire, 0x1234);
        BufMut::put_u32_le(&mut wire, 0xA1B2_C3D4);
        BufMut::put_u8(&mut wire, 0xEF);

        let mut slice: &[u8] = &wire;
        assert_eq!(Buf::get_u16(&mut slice), 0x1234);
        assert_eq!(Buf::get_u32_le(&mut slice), 0xA1B2_C3D4);
        assert_eq!(Buf::get_u8(&mut slice), 0xEF);
        assert_eq!(Buf::remaining(&slice), 0);

        let bytes = Bytes::copy_from_slice(&wire);
        let mut cursor = bytes.reader();
        assert_eq!(cursor.get_u16(), 0x1234);
        assert_eq!(cursor.get_u32_le(), 0xA1B2_C3D4);
        assert_eq!(cursor.get_u8(), 0xEF);
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn timer_wheel_fires_live_timers_at_deadline_boundaries() {
        let mut wheel = TimerWheel::with_config(
            Time::ZERO,
            TimerWheelConfig::new().max_timer_duration(Duration::from_secs(1)),
            CoalescingConfig::new(),
        );

        let fired_25 = Arc::new(AtomicUsize::new(0));
        let fired_50 = Arc::new(AtomicUsize::new(0));
        let fired_100 = Arc::new(AtomicUsize::new(0));

        let handle_50 =
            wheel.register(Time::from_millis(50), counting_waker(Arc::clone(&fired_50)));
        let _handle_100 = wheel.register(
            Time::from_millis(100),
            counting_waker(Arc::clone(&fired_100)),
        );
        let _handle_25 =
            wheel.register(Time::from_millis(25), counting_waker(Arc::clone(&fired_25)));

        assert_eq!(wheel.len(), 3);
        assert_eq!(wheel.next_deadline(), Some(Time::from_millis(25)));
        assert!(wheel.collect_expired(Time::from_millis(24)).is_empty());

        let ready = wheel.collect_expired(Time::from_millis(25));
        assert_eq!(ready.len(), 1, "only the 25ms timer should expire");
        wake_all(ready);
        assert_eq!(fired_25.load(Ordering::SeqCst), 1);
        assert_eq!(fired_50.load(Ordering::SeqCst), 0);
        assert_eq!(fired_100.load(Ordering::SeqCst), 0);

        assert!(wheel.cancel(&handle_50), "live timer must cancel once");
        assert!(
            !wheel.cancel(&handle_50),
            "cancel must be idempotent by handle generation"
        );

        let ready = wheel.collect_expired(Time::from_millis(100));
        wake_all(ready);
        assert_eq!(fired_25.load(Ordering::SeqCst), 1);
        assert_eq!(fired_50.load(Ordering::SeqCst), 0, "cancelled timer fired");
        assert_eq!(fired_100.load(Ordering::SeqCst), 1);
        assert!(wheel.is_empty());
    }

    #[test]
    fn timeout_future_uses_explicit_time_without_wall_clock_sleep() {
        let mut ready_timeout = TimeoutFuture::after(Time::ZERO, Duration::ZERO, ready(42_u8));
        let ready_result = with_task_context(|cx| ready_timeout.poll_with_time(cx, Time::ZERO));
        assert_eq!(ready_result, Poll::Ready(Ok(42)));

        let mut pending_timeout =
            TimeoutFuture::after(Time::ZERO, Duration::from_millis(10), pending::<()>());
        let pending_result =
            with_task_context(|cx| pending_timeout.poll_with_time(cx, Time::from_millis(9)));
        assert!(
            matches!(pending_result, Poll::Pending),
            "future should remain pending before the explicit deadline"
        );

        let elapsed_result =
            with_task_context(|cx| pending_timeout.poll_with_time(cx, Time::from_millis(10)));
        assert!(
            matches!(elapsed_result, Poll::Ready(Err(_))),
            "future should elapse at the explicit deadline"
        );
    }
}
