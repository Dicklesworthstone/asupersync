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
    fn read(
        reader: &mut InputReader,
        ctx: &mut Context<'_>,
        count: usize,
    ) -> Poll<io::Result<Vec<u8>>> {
        let mut bytes = vec![0; count];
        let mut buffer = ReadBuf::new(&mut bytes);
        Pin::new(reader)
            .poll_read(ctx, &mut buffer)
            .map(|result| result.map(|()| buffer.filled().to_vec()))
    }

    #[test]
    fn flush_requires_peer_acknowledgement_even_after_the_source_queue_is_empty() {
        let input = Input::new(4);
        let mut reader = InputReader(Arc::clone(&input));
        let (wake, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert_eq!(ready(input.poll_write(&mut ctx, b"data")), 4);
        assert_eq!(ready(read(&mut reader, &mut ctx, 4)), b"data");
        assert!(input.state.lock().bytes.is_empty());
        for _ in 0..20 {
            assert!(input.poll_flush(&mut ctx).is_pending());
        }
        assert_eq!(wake.0.load(Ordering::SeqCst), 0);
        input.acknowledged(3);
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert!(input.poll_flush(&mut ctx).is_pending());
        input.acknowledged(4);
        assert_eq!(wake.0.load(Ordering::SeqCst), 2);
        ready(input.poll_flush(&mut ctx));
    }

    #[test]
    fn bounded_writes_return_only_the_accepted_prefix_and_wake_after_reads() {
        let input = Input::new(3);
        let mut reader = InputReader(Arc::clone(&input));
        let (wake, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert_eq!(ready(input.poll_write(&mut ctx, b"abcdef")), 3);
        assert!(input.poll_write(&mut ctx, b"def").is_pending());
        assert_eq!(input.state.lock().accepted, 3);
        assert_eq!(ready(read(&mut reader, &mut ctx, 2)), b"ab");
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert_eq!(ready(input.poll_write(&mut ctx, b"def")), 2);
        assert_eq!(ready(read(&mut reader, &mut ctx, 3)), b"cde");
        assert_eq!(input.state.lock().high_water, 3);
        assert_eq!(input.state.lock().accepted, 5);
        assert_eq!(input.state.lock().acknowledged, 0);
    }

    #[test]
    fn empty_input_parks_until_explicit_eof_and_eof_preserves_queued_bytes() {
        let input = Input::new(4);
        let mut reader = InputReader(Arc::clone(&input));
        let (wake, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert!(read(&mut reader, &mut ctx, 4).is_pending());
        assert_eq!(wake.0.load(Ordering::SeqCst), 0);
        assert_eq!(ready(input.poll_write(&mut ctx, b"data")), 4);
        notify(input.stop(false));
        assert_eq!(ready(read(&mut reader, &mut ctx, 4)), b"data");
        assert!(ready(read(&mut reader, &mut ctx, 4)).is_empty());
        assert!(input.poll_flush(&mut ctx).is_pending());
        input.acknowledged(4);
        ready(input.poll_flush(&mut ctx));
        assert!(matches!(
            input.poll_write(&mut ctx, b"x"),
            Poll::Ready(Err(_))
        ));
    }

    #[test]
    fn aborted_input_wakes_a_pending_read_and_never_becomes_successful_eof() {
        let input = Input::new(4);
        let mut reader = InputReader(Arc::clone(&input));
        let (wake, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert!(read(&mut reader, &mut ctx, 4).is_pending());
        notify(input.stop(true));
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert!(matches!(
            read(&mut reader, &mut ctx, 4),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted
        ));
        assert!(matches!(input.poll_flush(&mut ctx), Poll::Ready(Err(_))));
    }

    #[test]
    fn retired_source_wakes_a_flush_but_leaves_terminal_classification_to_the_join() {
        let input = Input::new(4);
        let mut reader = InputReader(Arc::clone(&input));
        let (wake, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert_eq!(ready(input.poll_write(&mut ctx, b"data")), 4);
        assert_eq!(ready(read(&mut reader, &mut ctx, 4)), b"data");
        input.acknowledged(4);
        assert_eq!(ready(input.poll_write(&mut ctx, b"next")), 4);
        assert!(input.poll_flush(&mut ctx).is_pending());
        drop(reader);
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert!(input.poll_flush(&mut ctx).is_pending());
        assert!(input.poll_write(&mut ctx, b"late").is_pending());
        let state = input.state.lock();
        assert!(state.bytes.is_empty());
        assert_eq!((state.accepted, state.acknowledged), (8, 4));
    }
