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
    fn read(
        reader: &mut InputReader,
        ctx: &mut Context<'_>,
        size: usize,
    ) -> Poll<io::Result<Vec<u8>>> {
        let mut storage = vec![0; size];
        let mut buf = ReadBuf::new(&mut storage);
        Pin::new(reader)
            .poll_read(ctx, &mut buf)
            .map(|result| result.map(|()| buf.filled().to_vec()))
    }
    fn ready<T: std::fmt::Debug>(poll: Poll<io::Result<T>>) -> T {
        match poll {
            Poll::Ready(Ok(value)) => value,
            other => panic!("expected success: {other:?}"),
        }
    }

    #[test]
    fn full_input_parks_without_self_wakes_and_resumes_after_consumption() {
        let input = Input::new(3);
        let mut reader = InputReader(Arc::clone(&input));
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert_eq!(ready(input.poll_write(&mut ctx, b"abcdef")), 3);
        for _ in 0..20 {
            assert!(input.poll_write(&mut ctx, b"def").is_pending());
        }
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert_eq!(
            input.state.lock().accepted,
            3,
            "pending writes accept nothing"
        );
        assert_eq!(ready(read(&mut reader, &mut ctx, 2)), b"ab");
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(ready(input.poll_write(&mut ctx, b"def")), 2);
        assert_eq!(ready(read(&mut reader, &mut ctx, 3)), b"cde");
        assert_eq!(input.state.lock().high_water, 3);
    }

    #[test]
    fn empty_input_waits_for_data_and_explicit_eof_drains_the_final_tail() {
        let input = Input::new(7);
        let mut reader = InputReader(Arc::clone(&input));
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert!(read(&mut reader, &mut ctx, 3).is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert_eq!(ready(input.poll_write(&mut ctx, b"abcdefg")), 7);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        notify(input.stop(false));
        assert_eq!(ready(read(&mut reader, &mut ctx, 3)), b"abc");
        assert_eq!(ready(read(&mut reader, &mut ctx, 3)), b"def");
        assert_eq!(ready(read(&mut reader, &mut ctx, 3)), b"g");
        assert!(ready(read(&mut reader, &mut ctx, 3)).is_empty());
        assert!(matches!(
            input.poll_write(&mut ctx, b"x"),
            Poll::Ready(Err(_))
        ));
    }

    #[test]
    fn flush_requires_spool_acknowledgement_not_just_an_empty_pipe() {
        let input = Input::new(3);
        let mut reader = InputReader(Arc::clone(&input));
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        ready(input.poll_write(&mut ctx, b"abc"));
        assert_eq!(ready(read(&mut reader, &mut ctx, 3)), b"abc");
        assert!(input.state.lock().bytes.is_empty());
        assert!(input.poll_flush(&mut ctx).is_pending());
        input.on_spooled(2);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(input.poll_flush(&mut ctx).is_pending());
        input.on_spooled(3);
        ready(input.poll_flush(&mut ctx));
        assert_eq!(input.state.lock().spooled, 3);
    }

    #[test]
    fn abort_is_not_eof_and_reader_loss_wakes_a_full_producer() {
        let input = Input::new(1);
        let mut reader = InputReader(Arc::clone(&input));
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        ready(input.poll_write(&mut ctx, b"x"));
        assert!(input.poll_write(&mut ctx, b"y").is_pending());
        drop(reader);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(matches!(
            input.poll_write(&mut ctx, b"y"),
            Poll::Ready(Err(_))
        ));

        let input = Input::new(1);
        reader = InputReader(Arc::clone(&input));
        assert!(read(&mut reader, &mut ctx, 1).is_pending());
        notify(input.stop(true));
        assert!(matches!(read(&mut reader, &mut ctx, 1),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted));
        assert!(matches!(input.poll_flush(&mut ctx), Poll::Ready(Err(_))));
    }

    #[test]
    fn queue_wraparound_preserves_every_byte_under_all_small_capacities() {
        for capacity in 1..17 {
            let input = Input::new(capacity);
            let mut reader = InputReader(Arc::clone(&input));
            let mut ctx = Context::from_waker(Waker::noop());
            let expected: Vec<u8> = (0u8..=255).cycle().take(4097).collect();
            let mut accepted = 0;
            let mut observed = Vec::new();
            while observed.len() < expected.len() {
                if accepted < expected.len() {
                    match input.poll_write(&mut ctx, &expected[accepted..]) {
                        Poll::Ready(Ok(n)) => accepted += n,
                        Poll::Pending => {}
                        other @ Poll::Ready(_) => panic!("unexpected write: {other:?}"),
                    }
                }
                if accepted == expected.len() {
                    notify(input.stop(false));
                }
                observed.extend(ready(read(&mut reader, &mut ctx, 3)));
                input.on_spooled(observed.len() as u64);
                assert!(input.state.lock().bytes.len() <= capacity);
            }
            ready(input.poll_flush(&mut ctx));
            assert_eq!(observed, expected);
            assert!(ready(read(&mut reader, &mut ctx, 1)).is_empty());
            assert!(input.state.lock().high_water <= capacity);
        }
    }
