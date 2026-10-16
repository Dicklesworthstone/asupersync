    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn counter() -> (Arc<WakeCount>, Waker) {
        let count = Arc::new(WakeCount(AtomicUsize::new(0)));
        (Arc::clone(&count), Waker::from(count))
    }
    fn ready<T: std::fmt::Debug>(poll: Poll<io::Result<T>>) -> T {
        match poll {
            Poll::Ready(Ok(value)) => value,
            other => panic!("expected success: {other:?}"),
        }
    }
    fn read(output: &Output, ctx: &mut Context<'_>, count: usize) -> Poll<Vec<u8>> {
        let mut bytes = vec![0; count];
        let mut buffer = ReadBuf::new(&mut bytes);
        output
            .poll_read(ctx, &mut buffer)
            .map(|()| buffer.filled().to_vec())
    }

    #[test]
    fn empty_pipe_parks_without_spinning_and_only_latest_reader_is_woken() {
        let output = Output::new(3);
        let (stale, stale_waker) = counter();
        let (latest, latest_waker) = counter();
        let mut stale_ctx = Context::from_waker(&stale_waker);
        let mut latest_ctx = Context::from_waker(&latest_waker);
        assert!(read(&output, &mut stale_ctx, 2).is_pending());
        for _ in 0..20 {
            assert!(read(&output, &mut latest_ctx, 2).is_pending());
        }
        assert_eq!(latest.0.load(Ordering::SeqCst), 0);
        assert_eq!(ready(output.poll_write(&mut stale_ctx, b"abcde")), 3);
        assert_eq!(stale.0.load(Ordering::SeqCst), 0);
        assert_eq!(latest.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            read(&output, &mut latest_ctx, 2),
            Poll::Ready(b"ab".to_vec())
        );
        assert_eq!(
            read(&output, &mut latest_ctx, 2),
            Poll::Ready(b"c".to_vec())
        );
        assert!(read(&output, &mut latest_ctx, 2).is_pending());
        let state = output.state.lock();
        assert_eq!(
            (state.accepted, state.consumed, state.high_water),
            (3, 3, 3)
        );
    }

    #[test]
    fn epoch_flush_requires_full_consumption_and_never_acknowledges_buffering() {
        let output = Output::new(4);
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert_eq!(ready(output.poll_write(&mut ctx, b"abcd")), 4);
        assert!(output.poll_write(&mut ctx, b"next").is_pending());
        assert!(output.poll_flush(&mut ctx).is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert_eq!(read(&output, &mut ctx, 3), Poll::Ready(b"abc".to_vec()));
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(output.poll_flush(&mut ctx).is_pending());
        assert_eq!(read(&output, &mut ctx, 3), Poll::Ready(b"d".to_vec()));
        assert_eq!(count.0.load(Ordering::SeqCst), 2);
        ready(output.poll_flush(&mut ctx));
    }

    #[test]
    fn producer_drop_keeps_verified_bytes_but_cannot_create_eof() {
        let output = Output::new(4);
        let sink = OutputSink(Arc::clone(&output));
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert!(read(&output, &mut ctx, 4).is_pending());
        drop(sink);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(read(&output, &mut ctx, 4).is_pending());

        let sink = OutputSink(Arc::clone(&output));
        assert_eq!(ready(output.poll_write(&mut ctx, b"safe")), 4);
        drop(sink);
        assert_eq!(read(&output, &mut ctx, 4), Poll::Ready(b"safe".to_vec()));
        assert!(read(&output, &mut ctx, 4).is_pending());
    }

    #[test]
    fn cancellation_discards_unread_bytes_and_wakes_a_parked_epoch_flush() {
        let output = Output::new(4);
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert_eq!(ready(output.poll_write(&mut ctx, b"data")), 4);
        assert_eq!(read(&output, &mut ctx, 1), Poll::Ready(b"d".to_vec()));
        assert!(output.poll_flush(&mut ctx).is_pending());
        output.abort();
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(matches!(output.poll_flush(&mut ctx), Poll::Ready(Err(_))));
        assert!(matches!(
            output.poll_write(&mut ctx, b"x"),
            Poll::Ready(Err(_))
        ));
        let state = output.state.lock();
        assert!(state.bytes.is_empty());
        assert_eq!((state.accepted, state.consumed), (4, 1));
        drop(state);
        output.abort();
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn wraparound_reads_preserve_order_and_the_byte_bound() {
        let output = Output::new(7);
        let waker = Waker::noop();
        let mut ctx = Context::from_waker(waker);
        let input: Vec<u8> = (0..=255).cycle().take(2048).collect();
        let mut sent = 0;
        let mut received = Vec::new();
        while received.len() < input.len() {
            if sent < input.len() {
                if let Poll::Ready(Ok(count)) = output.poll_write(&mut ctx, &input[sent..]) {
                    sent += count;
                }
            }
            if let Poll::Ready(bytes) = read(&output, &mut ctx, 3) {
                received.extend_from_slice(&bytes);
            }
        }
        assert_eq!(received, input);
        assert_eq!(output.state.lock().high_water, 7);
        ready(output.poll_flush(&mut ctx));
    }
