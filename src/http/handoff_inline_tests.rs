    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Weak};
    use std::task::{Wake, Waker};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn close_wakes_all_parked_acceptors_and_refuses_new_ones() {
        let queue = HandoffQueue::default();
        let counts = [Arc::new(WakeCount::default()), Arc::new(WakeCount::default())];
        let wakers = counts.each_ref().map(|count| Waker::from(Arc::clone(count)));
        let mut first = std::pin::pin!(queue.accept());
        let mut second = std::pin::pin!(queue.accept());
        assert!(
            first
                .as_mut()
                .poll(&mut Context::from_waker(&wakers[0]))
                .is_pending()
        );
        assert!(
            second
                .as_mut()
                .poll(&mut Context::from_waker(&wakers[1]))
                .is_pending()
        );
        queue.close();
        for count in &counts {
            assert!(count.0.load(Ordering::Relaxed) > 0);
        }
        let mut cx = Context::from_waker(Waker::noop());
        for result in [first.as_mut().poll(&mut cx), second.as_mut().poll(&mut cx)] {
            match result {
                Poll::Ready(Err(error)) => assert_eq!(error.kind(), io::ErrorKind::BrokenPipe),
                _ => panic!("closed queue must finish every parked accept"),
            }
        }
        let mut late = std::pin::pin!(queue.accept());
        assert!(matches!(late.as_mut().poll(&mut cx), Poll::Ready(Err(_))));
    }

    struct DropProbe {
        queue: Weak<HandoffQueue>,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            let queue = self.queue.upgrade().expect("queue still owned");
            assert!(
                queue.state.try_lock().is_some(),
                "transport dropped under queue lock"
            );
            queue.close(); // A transport destructor may re-enter close.
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl AsyncRead for DropProbe {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for DropProbe {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn close_releases_queued_and_late_transports_outside_the_gate() {
        let queue = Arc::new(HandoffQueue::default());
        let drops = Arc::new(AtomicUsize::new(0));
        let stream = || {
            HandoffStream::new(Box::new(DropProbe {
                queue: Arc::downgrade(&queue),
                drops: Arc::clone(&drops),
            }))
        };
        queue.push(stream(), None);
        queue.push(stream(), None);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        queue.close();
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        queue.push(stream(), None);
        assert_eq!(drops.load(Ordering::Relaxed), 3);
        queue.close();
        assert!(queue.state.lock().connections.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn open_queue_keeps_fifo_and_peer_addresses() {
        let queue = HandoffQueue::default();
        let mut peers = Vec::new();
        for port in [1234, 5678] {
            let (stream, peer) = crate::io::duplex(8);
            peers.push(peer);
            queue.push(
                HandoffStream::new(Box::new(stream)),
                Some(SocketAddr::from(([127, 0, 0, 1], port))),
            );
        }
        let mut cx = Context::from_waker(Waker::noop());
        for port in [1234, 5678] {
            let mut accept = std::pin::pin!(queue.accept());
            match accept.as_mut().poll(&mut cx) {
                Poll::Ready(Ok((_, peer))) => {
                    assert_eq!(peer, Some(SocketAddr::from(([127, 0, 0, 1], port))));
                }
                _ => panic!("queued connection must be ready"),
            }
        }
        let mut accept = std::pin::pin!(queue.accept());
        assert!(accept.as_mut().poll(&mut cx).is_pending());
    }

    #[test]
    fn socket_byte_counter_tracks_bytes_written() {
        let (client, _server) = crate::io::duplex(64);
        let counter = Arc::new(AtomicU64::new(0));
        let mut counted = SocketByteCounter::new(client, Arc::clone(&counter));

        assert_eq!(counter.load(Ordering::Relaxed), 0);
        let mut cx = Context::from_waker(Waker::noop());
        let res = Pin::new(&mut counted).poll_write(&mut cx, b"hello world");
        assert!(matches!(res, Poll::Ready(Ok(11))));
        assert_eq!(counter.load(Ordering::Relaxed), 11);

        // DuplexStream gathers vectored writes (f48949393), so both slices fit
        // in the pipe's free space and the counter must see all six bytes. A
        // wrapper that fell back to the default poll_write_vectored would
        // write only "foo".
        assert!(counted.is_write_vectored());
        let slices = [io::IoSlice::new(b"foo"), io::IoSlice::new(b"bar")];
        let res2 = Pin::new(&mut counted).poll_write_vectored(&mut cx, &slices);
        assert!(matches!(res2, Poll::Ready(Ok(6))));
        assert_eq!(counter.load(Ordering::Relaxed), 17);
    }

    #[test]
    fn handoff_stream_preserves_socket_byte_counter() {
        let (client, _server) = crate::io::duplex(64);
        let counter = Arc::new(AtomicU64::new(42));
        let handoff = HandoffStream::with_socket_counter(Box::new(client), Arc::clone(&counter));
        assert!(handoff.socket_bytes_written_counter().is_some());
        assert_eq!(
            handoff
                .socket_bytes_written_counter()
                .unwrap()
                .load(Ordering::Relaxed),
            42
        );

        let (client2, _server2) = crate::io::duplex(64);
        let handoff_plain = HandoffStream::new(Box::new(client2));
        assert!(handoff_plain.socket_bytes_written_counter().is_none());
    }
