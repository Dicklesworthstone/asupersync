    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    #[derive(Default)]
    struct Duplex {
        input: &'static [u8],
        output: Vec<u8>,
        polls: usize,
        pending: bool,
        read_error: bool,
    }

    impl AsyncRead for Duplex {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.polls += 1;
            if self.pending {
                self.pending = false;
                return Poll::Pending;
            }
            let n = self.input.len().min(buf.remaining()).min(2);
            buf.put_slice(&self.input[..n]);
            self.input = &self.input[n..];
            Poll::Ready(if self.read_error {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "private error payload",
                ))
            } else {
                Ok(())
            })
        }
    }

    impl AsyncWrite for Duplex {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.polls += 1;
            let n = buf.len().min(2);
            self.output.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }
        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.polls += 1;
            Poll::Ready(Err(io::Error::from_raw_os_error(22)))
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.polls += 1;
            Poll::Ready(Ok(()))
        }
    }

    fn limits() -> IoCaptureLimits {
        IoCaptureLimits::new(32, 64, 64, 8)
    }
    fn cx() -> Context<'static> {
        Context::from_waker(Waker::noop())
    }
    fn value<T>(poll: Poll<io::Result<T>>) -> io::Result<T> {
        match poll {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("expected completion"),
        }
    }

    #[test]
    fn scalar_capture_replays_partial_progress_eof_and_native_errors() {
        let mut capture = RecordingIo::new(
            Duplex {
                input: b"ab",
                ..Duplex::default()
            },
            limits(),
        );
        let mut ctx = cx();
        assert_eq!(
            value(Pin::new(&mut capture).poll_write(&mut ctx, b"hello")).unwrap(),
            2
        );
        let mut bytes = [0; 5];
        let mut buf = ReadBuf::new(&mut bytes);
        buf.put_slice(b"x");
        value(Pin::new(&mut capture).poll_read(&mut ctx, &mut buf)).unwrap();
        assert_eq!(buf.filled(), b"xab");
        let original_error = value(Pin::new(&mut capture).poll_flush(&mut ctx)).unwrap_err();
        let mut eof = [0; 4];
        value(Pin::new(&mut capture).poll_read(&mut ctx, &mut ReadBuf::new(&mut eof))).unwrap();
        value(Pin::new(&mut capture).poll_shutdown(&mut ctx)).unwrap();
        let (inner, tape) = capture.into_parts();
        let tape = tape.unwrap();
        assert_eq!(
            (inner.polls, inner.output.as_slice()),
            (5, b"he".as_slice())
        );
        assert_eq!(
            (tape.operations(), tape.read_bytes(), tape.write_bytes()),
            (5, 2, 5)
        );
        let mut replay = tape.replay();
        assert_eq!(
            value(Pin::new(&mut replay).poll_write(&mut ctx, b"hello")).unwrap(),
            2
        );
        let mut bytes = [0; 5];
        let mut buf = ReadBuf::new(&mut bytes);
        buf.put_slice(b"x");
        value(Pin::new(&mut replay).poll_read(&mut ctx, &mut buf)).unwrap();
        assert_eq!(buf.filled(), b"xab");
        let error = value(Pin::new(&mut replay).poll_flush(&mut ctx)).unwrap_err();
        assert_eq!(
            (error.kind(), error.raw_os_error()),
            (original_error.kind(), original_error.raw_os_error())
        );
        let mut buf = ReadBuf::new(&mut eof);
        value(Pin::new(&mut replay).poll_read(&mut ctx, &mut buf)).unwrap();
        assert!(buf.filled().is_empty());
        value(Pin::new(&mut replay).poll_shutdown(&mut ctx)).unwrap();
        replay.verify_complete().unwrap();
        let error = value(Pin::new(&mut replay).poll_read(&mut ctx, &mut buf)).unwrap_err();
        assert_eq!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<IoReplayError>()
                .unwrap()
                .reason,
            IoReplayMismatch::Exhausted
        );
        assert!(matches!(
            replay.verify_complete(),
            Err(IoReplayCompletionError::Diverged(_))
        ));
    }

    #[test]
    fn capture_limits_never_change_the_underlying_write_result() {
        for limit in [
            IoCaptureLimits::new(0, 0, 0, 0),
            IoCaptureLimits::new(8, 0, 1, 0),
        ] {
            let mut capture = RecordingIo::new(Duplex::default(), limit);
            for _ in 0..3 {
                assert_eq!(
                    value(Pin::new(&mut capture).poll_write(&mut cx(), b"abc")).unwrap(),
                    2
                );
            }
            let (inner, result) = capture.into_parts();
            assert_eq!(inner.output, b"ababab");
            assert_eq!(inner.polls, 3);
            assert!(matches!(result, Err(IoCaptureError::Limit(_))));
        }
    }

    #[test]
    fn changed_unaccepted_write_tail_poison_is_shared_with_reads() {
        let mut capture = RecordingIo::new(Duplex::default(), limits());
        value(Pin::new(&mut capture).poll_write(&mut cx(), b"abc")).unwrap();
        let mut replay = capture.into_parts().1.unwrap().replay();
        let error = value(Pin::new(&mut replay).poll_write(&mut cx(), b"abX")).unwrap_err();
        let first = *error
            .get_ref()
            .unwrap()
            .downcast_ref::<IoReplayError>()
            .unwrap();
        assert_eq!(first.reason, IoReplayMismatch::Request);
        let mut bytes = [0xa5; 4];
        assert!(
            value(Pin::new(&mut replay).poll_read(&mut cx(), &mut ReadBuf::new(&mut bytes)))
                .is_err()
        );
        assert_eq!(bytes, [0xa5; 4]);
        assert_eq!(replay.failure(), Some(first));
        assert_eq!(replay.consumed_operations(), 0);
    }

    #[test]
    fn pending_source_poll_does_not_create_an_eof_or_completion_event() {
        let mut capture = RecordingIo::new(
            Duplex {
                input: b"ab",
                pending: true,
                ..Duplex::default()
            },
            limits(),
        );
        let mut bytes = [0; 2];
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(
            Pin::new(&mut capture)
                .poll_read(&mut cx(), &mut buf)
                .is_pending()
        );
        assert!(buf.filled().is_empty());
        value(Pin::new(&mut capture).poll_read(&mut cx(), &mut buf)).unwrap();
        let (inner, tape) = capture.into_parts();
        assert_eq!(inner.polls, 2);
        assert_eq!(tape.unwrap().operations(), 1);
    }

    #[test]
    fn cross_direction_prerequisite_wakes_without_polling_spin() {
        struct Count(AtomicUsize);
        impl Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let mut capture = RecordingIo::new(
            Duplex {
                input: b"ok",
                ..Duplex::default()
            },
            limits(),
        );
        value(Pin::new(&mut capture).poll_write(&mut cx(), b"go")).unwrap();
        let mut bytes = [0; 2];
        value(Pin::new(&mut capture).poll_read(&mut cx(), &mut ReadBuf::new(&mut bytes))).unwrap();
        let mut replay = capture.into_parts().1.unwrap().replay();
        let probe = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&probe));
        let mut ctx = Context::from_waker(&waker);
        let mut buf = ReadBuf::new(&mut bytes);
        for _ in 0..16 {
            assert!(
                Pin::new(&mut replay)
                    .poll_read(&mut ctx, &mut buf)
                    .is_pending()
            );
        }
        assert_eq!(probe.0.load(Ordering::SeqCst), 0);
        assert_eq!(
            replay.verify_complete(),
            Err(IoReplayCompletionError::Remaining { remaining: 2 })
        );
        value(Pin::new(&mut replay).poll_write(&mut cx(), b"go")).unwrap();
        assert_eq!(probe.0.load(Ordering::SeqCst), 1);
        value(Pin::new(&mut replay).poll_read(&mut ctx, &mut buf)).unwrap();
        assert_eq!(buf.filled(), b"ok");
        replay.verify_complete().unwrap();
    }

    #[test]
    fn vectored_write_keeps_boundaries_even_when_concatenated_bytes_match() {
        let mut capture = RecordingIo::new(Duplex::default(), limits());
        let bufs = [IoSlice::new(b"a"), IoSlice::new(b""), IoSlice::new(b"bc")];
        assert_eq!(
            value(Pin::new(&mut capture).poll_write_vectored(&mut cx(), &bufs)).unwrap(),
            1
        );
        let mut replay = capture.into_parts().1.unwrap().replay();
        let changed = [IoSlice::new(b"ab"), IoSlice::new(b""), IoSlice::new(b"c")];
        assert!(value(Pin::new(&mut replay).poll_write_vectored(&mut cx(), &changed)).is_err());
        assert_eq!(replay.failure().unwrap().reason, IoReplayMismatch::Request);
    }

    #[test]
    fn read_error_preserves_appended_bytes_without_retaining_private_error_text() {
        let mut capture = RecordingIo::new(
            Duplex {
                input: b"ok",
                read_error: true,
                ..Duplex::default()
            },
            limits(),
        );
        let mut bytes = [0; 2];
        let error =
            value(Pin::new(&mut capture).poll_read(&mut cx(), &mut ReadBuf::new(&mut bytes)))
                .unwrap_err();
        assert_eq!(error.to_string(), "private error payload");
        let tape = capture.into_parts().1.unwrap();
        assert!(!format!("{tape:?}").contains("private"));
        let mut replay = tape.replay();
        let mut output = [0; 2];
        let mut buf = ReadBuf::new(&mut output);
        let error = value(Pin::new(&mut replay).poll_read(&mut cx(), &mut buf)).unwrap_err();
        assert_eq!(buf.filled(), b"ok");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert!(error.get_ref().is_none());
        replay.verify_complete().unwrap();
    }

    #[test]
    fn caught_provider_panic_cannot_publish_a_partial_tape() {
        struct Panics(bool);
        impl AsyncWrite for Panics {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                if !self.0 {
                    self.0 = true;
                    panic!("source poll panic");
                }
                Poll::Ready(Ok(bytes.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let mut capture = RecordingIo::new(Panics(false), limits());
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = Pin::new(&mut capture).poll_write(&mut cx(), b"secret");
        }));
        assert!(failed.is_err());
        assert_eq!(
            capture.capture_error(),
            Some(IoCaptureError::InterruptedPoll)
        );
        assert_eq!(
            value(Pin::new(&mut capture).poll_write(&mut cx(), b"ok")).unwrap(),
            2
        );
        assert!(matches!(
            capture.into_parts().1,
            Err(IoCaptureError::InterruptedPoll)
        ));
    }

    #[test]
    fn replay_write_events_zeroize_digest() {
        let input = WriteInput::Scalar(b"confidential data payload");
        let digest = input.digest();
        assert_ne!(&*digest, &[0u8; 32]);
        let event = Event::Write {
            length: 25,
            slices: None,
            digest,
            accepted: 25,
            error: None,
        };
        drop(event);
    }

    #[test]
    fn capture_capacity_follows_recorded_operations_not_the_limit() {
        let mut limits = limits();
        limits.max_operations = 1_000_000;
        let mut capture = RecordingIo::new(Duplex::default(), limits);
        assert_eq!(capture.tape.events.capacity(), 0);
        for _ in 0..10 {
            value(Pin::new(&mut capture).poll_write(&mut cx(), b"x")).unwrap();
        }
        assert!(capture.tape.events.capacity() <= 64);
    }
