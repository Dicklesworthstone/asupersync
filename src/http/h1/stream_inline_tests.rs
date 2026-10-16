    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::CancelKind;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn counting_waker(counter: Arc<AtomicUsize>) -> Waker {
        struct CountingWaker {
            counter: Arc<AtomicUsize>,
        }

        use std::task::Wake;
        impl Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        Waker::from(Arc::new(CountingWaker { counter }))
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = std::pin::pin!(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn poll_body<B: Body + Unpin>(body: &mut B) -> Option<Result<Frame<B::Data>, B::Error>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        loop {
            match Pin::new(&mut *body).poll_frame(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
    ))]
    mod framed {
        use super::*;

        fn data(bytes: &'static [u8]) -> Option<Frame<BytesCursor>> {
            Some(Frame::data(BytesCursor::new(Bytes::from_static(bytes))))
        }

        fn send(
            writer: &mut FramedIncomingRequestBodyWriter,
            cx: &Cx,
            frame: &mut Option<Frame<BytesCursor>>,
        ) {
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            assert!(matches!(
                writer.poll_send_frame(cx, &mut task_cx, frame),
                Poll::Ready(Ok(()))
            ));
            assert!(frame.is_none());
        }

        #[test]
        fn declared_zero_and_last_data_wait_for_protocol_fin() {
            let cx = Cx::for_testing();
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            for declared in [0, 3] {
                let (mut writer, mut body) =
                    IncomingRequestBody::framed_channel_with_limits(&cx, Some(declared), 1, 16);
                assert!(!body.is_end_stream());
                assert!(Pin::new(&mut body).poll_frame(&mut task_cx).is_pending());
                if declared != 0 {
                    send(&mut writer, &cx, &mut data(b"abc"));
                    let frame = poll_body(&mut body).expect("DATA").expect("valid bytes");
                    assert_eq!(frame.into_data().expect("data").chunk(), b"abc");
                    assert!(!body.is_end_stream(), "declared bytes do not certify FIN");
                    assert!(Pin::new(&mut body).poll_frame(&mut task_cx).is_pending());
                }
                writer.finish(&cx).expect("validated FIN");
                assert!(poll_body(&mut body).is_none());
                assert!(body.is_end_stream());
                assert!(matches!(
                    poll_body(&mut body),
                    Some(Err(IncomingBodyError::AlreadyTerminal))
                ));
            }
        }

        #[test]
        fn raw_data_and_trailers_are_not_http1_framing_or_eof() {
            let cx = Cx::for_testing();
            let (writer, mut body) =
                IncomingRequestBody::framed_channel_with_limits(&cx, None, 2, 128);
            let mut writer = writer.max_trailers_size(64);
            send(&mut writer, &cx, &mut data(b"0\r\n\r\n5\r\nhello\r\n"));
            let received = poll_body(&mut body).expect("DATA").expect("raw DATA");
            assert_eq!(
                received.into_data().expect("data").chunk(),
                b"0\r\n\r\n5\r\nhello\r\n"
            );
            let mut trailers = HeaderMap::new();
            trailers.append(
                HeaderName::from_static("x-checksum"),
                HeaderValue::from_static("ok"),
            );
            send(&mut writer, &cx, &mut Some(Frame::trailers(trailers)));
            assert!(
                poll_body(&mut body)
                    .expect("trailers")
                    .expect("valid fields")
                    .is_trailers()
            );
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            assert!(!body.is_end_stream());
            assert!(Pin::new(&mut body).poll_frame(&mut task_cx).is_pending());
            writer.finish(&cx).expect("validated FIN after trailers");
            assert!(poll_body(&mut body).is_none());
        }

        #[test]
        #[cfg(feature = "http2-streaming")]
        fn receive_capacity_counts_delivered_data_after_wire_finish() {
            let cx = Cx::for_testing();
            let (mut writer, mut body) =
                IncomingRequestBody::framed_channel_with_limits(&cx, Some(5), 4, 128);
            let wake_count = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(Arc::clone(&wake_count));
            let mut task_cx = Context::from_waker(&waker);
            assert_eq!(writer.poll_consumed_data(&mut task_cx), 0);

            send(&mut writer, &cx, &mut data(b"ab"));
            send(&mut writer, &cx, &mut data(b"cde"));
            send(&mut writer, &cx, &mut data(b""));
            let mut trailers = HeaderMap::new();
            trailers.append(
                HeaderName::from_static("x-checksum"),
                HeaderValue::from_static("ok"),
            );
            send(&mut writer, &cx, &mut Some(Frame::trailers(trailers)));
            assert_eq!(writer.poll_consumed_data(&mut task_cx), 0);
            writer
                .finish(&cx)
                .expect("wire END_STREAM with queued body");
            assert_eq!(wake_count.load(Ordering::SeqCst), 0);

            let first = poll_body(&mut body)
                .expect("first DATA")
                .expect("valid DATA");
            assert_eq!(first.into_data().expect("DATA").chunk(), b"ab");
            assert_eq!(wake_count.load(Ordering::SeqCst), 1);
            assert_eq!(writer.poll_consumed_data(&mut task_cx), 2);
            assert_eq!(writer.poll_consumed_data(&mut task_cx), 0);

            let second = poll_body(&mut body)
                .expect("second DATA")
                .expect("valid DATA");
            assert_eq!(second.into_data().expect("DATA").chunk(), b"cde");
            assert_eq!(wake_count.load(Ordering::SeqCst), 2);
            let empty = poll_body(&mut body)
                .expect("empty DATA")
                .expect("valid DATA");
            assert_eq!(empty.into_data().expect("DATA").remaining(), 0);
            assert!(
                poll_body(&mut body)
                    .expect("trailer frame")
                    .expect("valid trailers")
                    .is_trailers()
            );
            assert_eq!(wake_count.load(Ordering::SeqCst), 2);
            assert_eq!(writer.poll_consumed_data(&mut task_cx), 3);
            assert!(poll_body(&mut body).is_none());
            assert_eq!(writer.poll_consumed_data(&mut task_cx), 0);
        }

        #[test]
        #[cfg(feature = "http2-streaming")]
        fn receive_capacity_excludes_pending_and_abandoned_frames() {
            for byte_limit in [2, 4] {
                let cx = Cx::for_testing();
                let (mut writer, mut body) =
                    IncomingRequestBody::framed_channel_with_limits(&cx, None, 1, byte_limit);
                let waker = noop_waker();
                let mut task_cx = Context::from_waker(&waker);
                assert_eq!(writer.poll_consumed_data(&mut task_cx), 0);
                send(&mut writer, &cx, &mut data(b"x"));
                let prefix = poll_body(&mut body).expect("prefix").expect("valid DATA");
                assert_eq!(prefix.into_data().expect("DATA").chunk(), b"x");
                send(&mut writer, &cx, &mut data(b"ab"));
                let mut pending = data(b"cd");
                assert!(
                    writer
                        .poll_send_frame(&cx, &mut task_cx, &mut pending)
                        .is_pending()
                );
                assert!(pending.is_none());
                assert_eq!(body.queued_frames(), if byte_limit == 2 { 1 } else { 2 });
                writer.fail(IncomingBodyError::ClientAborted);
                drop(body);

                assert_eq!(writer.shared.queued_bytes.state.lock().queued, 0);
                assert_eq!(writer.shared.queued_bytes.state.lock().queued_frames, 0);
                assert_eq!(writer.poll_consumed_data(&mut task_cx), 1);
                assert_eq!(writer.poll_consumed_data(&mut task_cx), 0);
            }
        }

        #[test]
        #[cfg(feature = "http2-streaming")]
        fn receive_capacity_excludes_consumer_policy_rejection() {
            let cx = Cx::for_testing();
            let (mut writer, mut body) =
                IncomingRequestBody::framed_channel_with_limits(&cx, None, 1, 8);
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            assert_eq!(writer.poll_consumed_data(&mut task_cx), 0);
            send(&mut writer, &cx, &mut data(b"abc"));
            body.tighten_max_body_size(2);
            assert_eq!(
                poll_body(&mut body)
                    .expect("policy error")
                    .expect_err("oversize DATA"),
                IncomingBodyError::BodyTooLarge {
                    actual: Some(3),
                    limit: 2,
                }
            );
            assert_eq!(body.queued_bytes(), 0);
            assert_eq!(writer.poll_consumed_data(&mut task_cx), 0);
        }

        #[test]
        #[cfg(feature = "http2-streaming")]
        fn receive_capacity_wake_runs_outside_shared_locks() {
            struct InspectWake {
                shared: Arc<IncomingBodyShared>,
                wake_count: AtomicUsize,
            }
            impl std::task::Wake for InspectWake {
                fn wake(self: Arc<Self>) {
                    assert!(self.shared.framed_consumed_waker.try_lock().is_some());
                    assert!(self.shared.framed_consumer_waker.try_lock().is_some());
                    assert!(self.shared.queued_bytes.state.try_lock().is_some());
                    assert_eq!(self.shared.framed_consumed_data.load(Ordering::Acquire), 2);
                    self.wake_count.fetch_add(1, Ordering::SeqCst);
                }
            }
            let cx = Cx::for_testing();
            let (mut writer, mut body) =
                IncomingRequestBody::framed_channel_with_limits(&cx, None, 1, 8);
            let probe = Arc::new(InspectWake {
                shared: Arc::clone(&writer.shared),
                wake_count: AtomicUsize::new(0),
            });
            let waker = Waker::from(Arc::clone(&probe));
            let mut task_cx = Context::from_waker(&waker);
            assert_eq!(writer.poll_consumed_data(&mut task_cx), 0);
            send(&mut writer, &cx, &mut data(b"ab"));
            let frame = poll_body(&mut body).expect("DATA").expect("valid DATA");
            assert_eq!(frame.into_data().expect("DATA").chunk(), b"ab");
            assert_eq!(probe.wake_count.load(Ordering::SeqCst), 1);
            assert_eq!(writer.poll_consumed_data(&mut task_cx), 2);
        }

        #[test]
        #[cfg(feature = "http2-streaming")]
        fn receive_capacity_waker_replacement_and_writer_drop_release_outside_lock() {
            struct DropProbe {
                shared: Arc<IncomingBodyShared>,
                drops: Arc<AtomicUsize>,
            }
            // A probe, not a no-op: its Drop observes where the waker is released.
            #[allow(clippy::manual_noop_waker)]
            impl std::task::Wake for DropProbe {
                fn wake(self: Arc<Self>) {}
            }
            impl Drop for DropProbe {
                fn drop(&mut self) {
                    assert!(self.shared.framed_consumed_waker.try_lock().is_some());
                    self.drops.fetch_add(1, Ordering::SeqCst);
                }
            }
            let cx = Cx::for_testing();
            let (writer, _body) = IncomingRequestBody::framed_channel_with_limits(&cx, None, 1, 8);
            let drops = Arc::new(AtomicUsize::new(0));
            for expected_drops in 0..2 {
                let waker = Waker::from(Arc::new(DropProbe {
                    shared: Arc::clone(&writer.shared),
                    drops: Arc::clone(&drops),
                }));
                let mut task_cx = Context::from_waker(&waker);
                assert_eq!(writer.poll_consumed_data(&mut task_cx), 0);
                assert_eq!(drops.load(Ordering::SeqCst), expected_drops);
            }
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            drop(writer);
            assert_eq!(drops.load(Ordering::SeqCst), 2);
        }

        #[test]
        fn byte_and_frame_backpressure_retain_exact_pending_frame() {
            let cx = Cx::for_testing();
            // One case waits for a byte permit; the other already holds its
            // byte permit and waits for the single MPSC frame slot.
            for byte_limit in [2, 4] {
                let (mut writer, mut body) =
                    IncomingRequestBody::framed_channel_with_limits(&cx, None, 1, byte_limit);
                send(&mut writer, &cx, &mut data(b"ab"));
                let wake_count = Arc::new(AtomicUsize::new(0));
                let waker = counting_waker(Arc::clone(&wake_count));
                let mut task_cx = Context::from_waker(&waker);
                let mut offered = data(b"cd");
                assert!(
                    writer
                        .poll_send_frame(&cx, &mut task_cx, &mut offered)
                        .is_pending()
                );
                assert!(offered.is_none(), "writer owns the exact pending frame");
                assert!(writer.has_pending_frame());
                assert!(body.queued_bytes() <= byte_limit);
                assert_eq!(body.queued_frames(), if byte_limit == 2 { 1 } else { 2 });
                let before = wake_count.load(Ordering::SeqCst);
                let first = poll_body(&mut body)
                    .expect("first frame")
                    .expect("first bytes");
                assert_eq!(first.into_data().expect("data").chunk(), b"ab");
                assert!(
                    wake_count.load(Ordering::SeqCst) > before,
                    "consumption rearms writer"
                );
                assert!(matches!(
                    writer.poll_send_frame(&cx, &mut task_cx, &mut offered),
                    Poll::Ready(Ok(()))
                ));
                assert!(!writer.has_pending_frame());
                let second = poll_body(&mut body)
                    .expect("second frame")
                    .expect("second bytes");
                assert_eq!(second.into_data().expect("data").chunk(), b"cd");
                assert_eq!(body.queued_bytes(), 0);
                assert_eq!(body.queued_frames(), 0);
                writer.finish(&cx).expect("FIN");
                assert!(poll_body(&mut body).is_none());
            }
        }

        #[test]
        fn overrun_underrun_and_forbidden_trailers_fail_closed() {
            let cx = Cx::for_testing();
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            let (mut writer, mut body) =
                IncomingRequestBody::framed_channel_with_limits(&cx, Some(1), 1, 32);
            let mut offered = data(b"ab");
            assert!(matches!(
                writer.poll_send_frame(&cx, &mut task_cx, &mut offered),
                Poll::Ready(Err(IncomingBodyError::BadContentLength))
            ));
            assert!(offered.is_some(), "rejected bytes never enter channel");
            assert_eq!(body.queued_bytes(), 0);
            assert!(matches!(
                poll_body(&mut body),
                Some(Err(IncomingBodyError::BadContentLength))
            ));

            let (mut writer, mut body) =
                IncomingRequestBody::framed_channel_with_limits(&cx, Some(2), 1, 32);
            send(&mut writer, &cx, &mut data(b"a"));
            assert!(poll_body(&mut body).expect("prefix").is_ok());
            assert_eq!(writer.finish(&cx), Err(IncomingBodyError::BadContentLength));
            assert!(matches!(
                poll_body(&mut body),
                Some(Err(IncomingBodyError::BadContentLength))
            ));

            let (mut writer, mut body) =
                IncomingRequestBody::framed_channel_with_limits(&cx, None, 1, 64);
            let mut trailers = HeaderMap::new();
            trailers.append(
                HeaderName::from_static("content-length"),
                HeaderValue::from_static("0"),
            );
            let mut offered = Some(Frame::trailers(trailers));
            assert!(matches!(
                writer.poll_send_frame(&cx, &mut task_cx, &mut offered),
                Poll::Ready(Err(IncomingBodyError::BadHeader))
            ));
            assert!(offered.is_some());
            assert!(matches!(
                poll_body(&mut body),
                Some(Err(IncomingBodyError::BadHeader))
            ));
        }

        #[test]
        fn trailers_do_not_hide_later_source_failure() {
            let cx = Cx::for_testing();
            let (mut writer, mut body) =
                IncomingRequestBody::framed_channel_with_limits(&cx, Some(0), 1, 32);
            send(
                &mut writer,
                &cx,
                &mut Some(Frame::trailers(HeaderMap::new())),
            );
            assert!(
                poll_body(&mut body)
                    .expect("trailers")
                    .expect("valid empty fields")
                    .is_trailers()
            );
            drop(writer);
            assert!(matches!(
                poll_body(&mut body),
                Some(Err(IncomingBodyError::SourceDisconnected))
            ));
        }

        #[test]
        fn failed_pending_send_releases_permits_and_preserves_first_error() {
            let cx = Cx::for_testing();
            let (mut writer, mut body) =
                IncomingRequestBody::framed_channel_with_limits(&cx, None, 1, 4);
            send(&mut writer, &cx, &mut data(b"ab"));
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut offered = data(b"cd");
            assert!(
                writer
                    .poll_send_frame(&cx, &mut task_cx, &mut offered)
                    .is_pending()
            );
            assert_eq!(body.queued_bytes(), 4, "pending send owns second permit");
            assert_eq!(body.queued_frames(), 2);
            writer.fail(IncomingBodyError::ClientAborted);
            writer.fail(IncomingBodyError::SourceDisconnected);
            assert_eq!(body.queued_bytes(), 2);
            assert_eq!(body.queued_frames(), 1);
            let first = poll_body(&mut body)
                .expect("accepted prefix")
                .expect("valid prefix");
            assert_eq!(first.into_data().expect("data").chunk(), b"ab");
            assert!(matches!(
                poll_body(&mut body),
                Some(Err(IncomingBodyError::ClientAborted))
            ));
            assert_eq!(body.queued_bytes(), 0);
            assert_eq!(body.queued_frames(), 0);
        }

        #[test]
        fn pending_byte_and_frame_waits_wake_on_request_cancellation() {
            for byte_limit in [2, 4] {
                let cx = Cx::for_testing();
                let (mut writer, body) =
                    IncomingRequestBody::framed_channel_with_limits(&cx, None, 1, byte_limit);
                send(&mut writer, &cx, &mut data(b"ab"));
                let wake_count = Arc::new(AtomicUsize::new(0));
                let waker = counting_waker(Arc::clone(&wake_count));
                let mut task_cx = Context::from_waker(&waker);
                let mut offered = data(b"cd");
                assert!(
                    writer
                        .poll_send_frame(&cx, &mut task_cx, &mut offered)
                        .is_pending()
                );
                assert!(offered.is_none());
                assert_eq!(body.queued_frames(), if byte_limit == 2 { 1 } else { 2 });
                let before = wake_count.load(Ordering::SeqCst);
                cx.cancel_fast(CancelKind::Deadline);
                assert!(wake_count.load(Ordering::SeqCst) > before);
                assert!(matches!(
                    writer.poll_send_frame(&cx, &mut task_cx, &mut offered),
                    Poll::Ready(Err(IncomingBodyError::Cancelled {
                        kind: CancelKind::Deadline,
                    }))
                ));
                assert!(!writer.has_pending_frame());
                assert!(writer.cancel_registration.is_none());
                assert_eq!(body.queued_bytes(), 2);
                drop(body);
                assert_eq!(writer.shared.queued_bytes.state.lock().queued, 0);
                assert_eq!(writer.shared.queued_bytes.state.lock().queued_frames, 0);
            }
        }

        #[test]
        fn typed_transport_failure_precedes_owner_cancellation() {
            let cx = Cx::for_testing();
            let (mut writer, mut body) =
                IncomingRequestBody::framed_channel_with_limits(&cx, None, 1, 8);
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            assert!(Pin::new(&mut body).poll_frame(&mut task_cx).is_pending());
            writer.fail(IncomingBodyError::ClientAborted);
            cx.cancel_fast(CancelKind::ParentCancelled);
            assert!(matches!(
                poll_body(&mut body),
                Some(Err(IncomingBodyError::ClientAborted))
            ));
        }

        #[test]
        fn consumer_policy_failure_wakes_idle_driver_with_exact_error() {
            let cx = Cx::for_testing();
            let (writer, mut body) =
                IncomingRequestBody::framed_channel_with_limits(&cx, None, 1, 8);
            let mut writer = writer.max_body_size(8);
            send(&mut writer, &cx, &mut data(b"abc"));
            let wake_count = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(Arc::clone(&wake_count));
            let mut task_cx = Context::from_waker(&waker);
            assert!(writer.poll_consumer_dropped(&mut task_cx).is_pending());
            body.tighten_max_body_size(2);
            let expected = IncomingBodyError::BodyTooLarge {
                actual: Some(3),
                limit: 2,
            };
            assert!(matches!(poll_body(&mut body), Some(Err(error)) if error == expected));
            assert!(wake_count.load(Ordering::SeqCst) > 0);
            assert!(
                !writer.consumer_dropped(),
                "failure is not normal early response"
            );
            assert_eq!(
                writer.poll_consumer_dropped(&mut task_cx),
                Poll::Ready(Err(expected))
            );
        }

        #[test]
        fn consumer_cancellation_wakes_idle_driver_with_exact_kind() {
            let cx = Cx::for_testing();
            let (writer, mut body) =
                IncomingRequestBody::framed_channel_with_limits(&cx, None, 1, 8);
            let wake_count = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(Arc::clone(&wake_count));
            let mut task_cx = Context::from_waker(&waker);
            assert!(writer.poll_consumer_dropped(&mut task_cx).is_pending());
            assert!(Pin::new(&mut body).poll_frame(&mut task_cx).is_pending());
            cx.cancel_fast(CancelKind::Deadline);
            let after_cancel = wake_count.load(Ordering::SeqCst);
            let expected = IncomingBodyError::Cancelled {
                kind: CancelKind::Deadline,
            };
            assert!(matches!(poll_body(&mut body), Some(Err(error)) if error == expected));
            assert!(wake_count.load(Ordering::SeqCst) > after_cancel);
            assert!(!writer.consumer_dropped());
            assert_eq!(
                writer.poll_consumer_dropped(&mut task_cx),
                Poll::Ready(Err(expected))
            );
        }

        #[test]
        fn idle_consumer_drop_wakes_outside_shared_locks() {
            struct InspectWake {
                shared: Arc<IncomingBodyShared>,
                wake_count: AtomicUsize,
            }
            impl std::task::Wake for InspectWake {
                fn wake(self: Arc<Self>) {
                    self.wake_by_ref();
                }
                fn wake_by_ref(self: &Arc<Self>) {
                    assert!(self.shared.framed_consumer_waker.try_lock().is_some());
                    assert!(self.shared.queued_bytes.state.try_lock().is_some());
                    assert!(self.shared.framed_consumer_error.try_lock().is_some());
                    self.wake_count.fetch_add(1, Ordering::SeqCst);
                }
            }
            let cx = Cx::for_testing();
            let (writer, body) = IncomingRequestBody::framed_channel_with_limits(&cx, None, 1, 8);
            let probe = Arc::new(InspectWake {
                shared: Arc::clone(&writer.shared),
                wake_count: AtomicUsize::new(0),
            });
            let waker = Waker::from(Arc::clone(&probe));
            let mut task_cx = Context::from_waker(&waker);
            assert!(writer.poll_consumer_dropped(&mut task_cx).is_pending());
            drop(body);
            assert!(probe.wake_count.load(Ordering::SeqCst) > 0);
            assert!(writer.consumer_dropped());
            assert_eq!(
                writer.poll_consumer_dropped(&mut task_cx),
                Poll::Ready(Ok(()))
            );
        }

        #[test]
        fn replacing_idle_driver_waker_drops_it_outside_shared_lock() {
            struct DropProbe {
                shared: Arc<IncomingBodyShared>,
                drops: Arc<AtomicUsize>,
            }
            // A probe, not a no-op: its Drop observes where the waker is released.
            #[allow(clippy::manual_noop_waker)]
            impl std::task::Wake for DropProbe {
                fn wake(self: Arc<Self>) {}
            }
            impl Drop for DropProbe {
                fn drop(&mut self) {
                    assert!(self.shared.framed_consumer_waker.try_lock().is_some());
                    self.drops.fetch_add(1, Ordering::SeqCst);
                }
            }
            let cx = Cx::for_testing();
            let (writer, _body) = IncomingRequestBody::framed_channel_with_limits(&cx, None, 1, 8);
            let drops = Arc::new(AtomicUsize::new(0));
            {
                let waker = Waker::from(Arc::new(DropProbe {
                    shared: Arc::clone(&writer.shared),
                    drops: Arc::clone(&drops),
                }));
                let mut task_cx = Context::from_waker(&waker);
                assert!(writer.poll_consumer_dropped(&mut task_cx).is_pending());
            }
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            assert!(writer.poll_consumer_dropped(&mut task_cx).is_pending());
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn body_kind_properties() {
        assert!(BodyKind::Empty.is_empty());
        assert!(BodyKind::ContentLength(0).is_empty());
        assert!(!BodyKind::ContentLength(10).is_empty());
        assert!(!BodyKind::Chunked.is_empty());

        assert!(!BodyKind::Empty.is_chunked());
        assert!(!BodyKind::ContentLength(10).is_chunked());
        assert!(BodyKind::Chunked.is_chunked());

        assert_eq!(BodyKind::Empty.exact_size(), Some(0));
        assert_eq!(BodyKind::ContentLength(42).exact_size(), Some(42));
        assert_eq!(BodyKind::Chunked.exact_size(), None);
    }

    #[test]
    fn incoming_body_content_length() {
        let cx: Cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(5));

        block_on(writer.push_bytes(&cx, b"hello")).expect("push bytes");

        let frame = poll_body(&mut body).unwrap().unwrap();
        let data = frame.into_data().unwrap();
        assert_eq!(data.chunk(), b"hello");
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_content_length_hint_tracks_delivered_bytes() {
        let cx: Cx = Cx::for_testing();
        let (writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(5));
        let mut writer = writer.max_chunk_size(2);

        block_on(writer.push_bytes(&cx, b"hello")).expect("push bytes");

        let first = poll_body(&mut body)
            .expect("first data frame")
            .expect("first frame should be valid");
        assert_eq!(first.into_data().expect("first data").chunk(), b"he");
        assert_eq!(body.size_hint().exact(), Some(3));

        let second = poll_body(&mut body)
            .expect("second data frame")
            .expect("second frame should be valid");
        assert_eq!(second.into_data().expect("second data").chunk(), b"ll");
        assert_eq!(body.size_hint().exact(), Some(1));

        let third = poll_body(&mut body)
            .expect("third data frame")
            .expect("third frame should be valid");
        assert_eq!(third.into_data().expect("third data").chunk(), b"o");
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_unfinished_producer_drop_is_not_eof() {
        let cx: Cx = Cx::for_testing();
        let (writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(5));

        drop(writer);

        let result = poll_body(&mut body).expect("unfinished producer must yield an error");
        assert!(matches!(result, Err(IncomingBodyError::SourceDisconnected)));
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_completed_chunked_without_trailers_ends_cleanly() {
        let cx: Cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);

        block_on(writer.push_bytes(&cx, b"0\r\n\r\n")).expect("finish chunked body");

        assert!(poll_body(&mut body).is_none());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_chunked_with_trailers() {
        let cx: Cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);

        block_on(writer.push_bytes(&cx, b"5\r\nhello\r\n0\r\nX-Trailer: test\r\n\r\n"))
            .expect("push bytes");

        let frame = poll_body(&mut body).unwrap().unwrap();
        assert_eq!(frame.into_data().unwrap().chunk(), b"hello");

        let frame = poll_body(&mut body).unwrap().unwrap();
        let trailers = frame.into_trailers().unwrap();
        assert_eq!(trailers.len(), 1);

        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_chunked_trailer_limit_does_not_count_terminal_crlf() {
        let cx: Cx = Cx::for_testing();
        let (writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);
        let mut writer = writer.max_trailers_size(7);

        // "X: y\r\n" consumes 6 trailer bytes; terminal "\r\n" should not count.
        block_on(writer.push_bytes(&cx, b"0\r\nX: y\r\n\r\n"))
            .expect("valid trailers should fit configured trailer limit");

        let frame = poll_body(&mut body)
            .expect("trailers frame")
            .expect("ok frame");
        let trailers = frame.into_trailers().expect("trailers");
        assert_eq!(trailers.len(), 1);
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_pending_poll_keeps_waker_registration() {
        let cx: Cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(1));

        let wake_count = Arc::new(AtomicUsize::new(0));
        let frame_waker = counting_waker(Arc::clone(&wake_count));
        let mut task_cx = Context::from_waker(&frame_waker);

        let first = Pin::new(&mut body).poll_frame(&mut task_cx);
        assert!(matches!(first, Poll::Pending));

        block_on(writer.push_bytes(&cx, b"x")).expect("push bytes");
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);

        let second = Pin::new(&mut body).poll_frame(&mut task_cx);
        let frame = match second {
            Poll::Ready(Some(Ok(frame))) => frame,
            _other => return, // Ignore in this test
        };
        let data = frame.into_data().expect("data frame");
        assert_eq!(data.chunk(), b"x");
    }

    #[test]
    fn incoming_body_chunked_finish_incomplete_errors() {
        let cx: Cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);

        block_on(writer.push_bytes(&cx, b"5\r\nhello\r\n")).expect("push bytes");
        let err = writer.finish(&cx).expect_err("finish should error");
        assert!(matches!(err, IncomingBodyError::BadChunkedEncoding));

        let frame = poll_body(&mut body)
            .expect("queued data frame")
            .expect("queued data remains valid");
        assert_eq!(frame.into_data().expect("data frame").chunk(), b"hello");
        let terminal = poll_body(&mut body).expect("framing error after queued data");
        assert!(matches!(
            terminal,
            Err(IncomingBodyError::BadChunkedEncoding)
        ));
        assert!(body.is_end_stream());
    }

    /// A chunk-size line longer than the buffered codec's limit used to be
    /// buffered (up to 256 KiB) and rescanned from its start on every read.
    #[test]
    fn incoming_chunk_size_line_is_bounded() {
        let cx: Cx = Cx::for_testing();
        let (mut writer, _body) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);
        writer.buffer.extend_from_slice(b"1;");
        writer.buffer.extend_from_slice(&[b'a'; 2048]);
        assert!(matches!(
            writer.try_decode_frame(),
            Err(HttpError::BadChunkedEncoding)
        ));
    }

    /// Extensions are not body bytes, so the body limit never charged them:
    /// a client could send a kilobyte of extension per byte of body without
    /// end. They are bounded by the data received plus 16 KiB.
    #[test]
    fn incoming_chunk_extensions_are_bounded_by_the_data_received() {
        let cx: Cx = Cx::for_testing();
        let (mut writer, _body) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);
        let mut line = b"1;e=".to_vec();
        line.resize(1000, b'a');
        line.extend_from_slice(b"\r\nX\r\n");
        let mut frames = 0usize;
        let error = loop {
            writer.buffer.extend_from_slice(&line);
            match writer.try_decode_frame() {
                Ok(Some(_)) => frames += 1,
                Ok(None) => panic!("a whole chunk was buffered"),
                Err(error) => break error,
            }
            assert!(frames < 64, "extensions were never bounded");
        };
        assert!(matches!(error, HttpError::BadChunkedEncoding));
        assert_eq!(frames, 16, "16 KiB of allowance, then one byte per line");

        // Ordinary per-chunk extensions, such as signatures on each chunk of
        // a signed upload, stay within the budget.
        let (mut writer, _body) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);
        let mut chunk = format!("400;chunk-signature={}\r\n", "f".repeat(64)).into_bytes();
        chunk.extend_from_slice(&[b'd'; 0x400]);
        chunk.extend_from_slice(b"\r\n");
        for _ in 0..64 {
            writer.buffer.extend_from_slice(&chunk);
            let frame = writer
                .try_decode_frame()
                .expect("a signed chunk is accepted")
                .expect("a whole chunk decodes");
            assert_eq!(frame.into_data().expect("data").remaining(), 0x400);
        }
    }

    #[test]
    fn incoming_body_limit_refuses_whole_crossing_frame_and_surfaces_error() {
        let cx: Cx = Cx::for_testing();
        let (writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(4));
        let mut writer = writer.max_chunk_size(2).max_body_size(3);

        let error = block_on(writer.push_bytes(&cx, b"data"))
            .expect_err("second two-byte frame crosses the three-byte limit");
        assert!(matches!(error, IncomingBodyError::BodyTooLarge { .. }));

        let frame = poll_body(&mut body)
            .expect("first frame remains queued")
            .expect("first frame is within the limit");
        assert_eq!(frame.into_data().expect("data frame").chunk(), b"da");
        let terminal = poll_body(&mut body).expect("limit error follows accepted frame");
        assert!(matches!(
            terminal,
            Err(IncomingBodyError::BodyTooLarge { .. })
        ));
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_repoll_after_eof_fails_closed() {
        let cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(1));

        block_on(writer.push_bytes(&cx, b"x")).expect("one-byte body");
        let frame = poll_body(&mut body)
            .expect("data frame")
            .expect("valid data frame");
        assert_eq!(frame.into_data().expect("data").chunk(), b"x");
        assert!(poll_body(&mut body).is_none(), "first terminal poll is EOF");
        assert!(matches!(
            poll_body(&mut body),
            Some(Err(IncomingBodyError::AlreadyTerminal))
        ));
    }

    #[test]
    fn v0_4_3_compatibility_incoming_body_preserves_http_error_and_repeat_eof_contract() {
        let cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingBody::channel(&cx, BodyKind::ContentLength(1));

        block_on(writer.push_bytes(&cx, b"x")).expect("legacy one-byte body");
        let frame = poll_body(&mut body)
            .expect("legacy data frame")
            .expect("valid legacy data frame");
        assert_eq!(frame.into_data().expect("legacy data").chunk(), b"x");
        assert!(poll_body(&mut body).is_none(), "legacy first terminal poll");
        assert!(
            poll_body(&mut body).is_none(),
            "0.4.3 legacy bodies must keep returning EOF after termination"
        );

        let (writer, mut unfinished) = IncomingBody::channel(&cx, BodyKind::ContentLength(1));
        drop(writer);
        assert!(matches!(
            poll_body(&mut unfinished),
            Some(Err(HttpError::BodyChannelClosed))
        ));
        assert!(poll_body(&mut unfinished).is_none());

        let (mut limited_writer, _limited_body) =
            IncomingBody::channel(&cx, BodyKind::ContentLength(1));
        limited_writer = limited_writer.max_body_size(0);
        assert!(matches!(
            block_on(limited_writer.push_bytes(&cx, b"x")),
            Err(HttpError::BodyTooLarge)
        ));

        let (mut malformed_writer, _malformed_body) = IncomingBody::channel(&cx, BodyKind::Chunked);
        assert!(matches!(
            block_on(malformed_writer.push_bytes(&cx, b"0\r\nnot-a-field\r\n\r\n")),
            Err(HttpError::BadHeader)
        ));
    }

    #[test]
    fn incoming_body_cancellation_preserves_exact_kind() {
        let base_cx = Cx::for_testing();
        let (mut writer, mut body) =
            IncomingRequestBody::channel(&base_cx, BodyKind::ContentLength(1));
        let cancelled_cx = Cx::for_testing();
        cancelled_cx.cancel_fast(CancelKind::Deadline);

        let error = block_on(writer.push_bytes(&cancelled_cx, b"x"))
            .expect_err("cancelled producer must fail");
        assert_eq!(
            error,
            IncomingBodyError::Cancelled {
                kind: CancelKind::Deadline,
            }
        );
        assert!(matches!(
            poll_body(&mut body),
            Some(Err(IncomingBodyError::Cancelled {
                kind: CancelKind::Deadline,
            }))
        ));
    }

    #[test]
    fn incoming_body_queue_bytes_backpressure_independently_of_frame_slots() {
        let cx = Cx::for_testing();
        let (writer, mut body) =
            IncomingRequestBody::channel_with_limits(&cx, BodyKind::ContentLength(4), 8, 2);
        let mut writer = writer.max_chunk_size(2);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        {
            let mut push = std::pin::pin!(writer.push_bytes(&cx, b"data"));
            assert!(matches!(push.as_mut().poll(&mut task_cx), Poll::Pending));
            assert_eq!(body.queued_bytes(), 2);
            assert_eq!(body.queued_bytes_peak(), 2);

            let first = poll_body(&mut body)
                .expect("first frame")
                .expect("valid first frame");
            assert_eq!(first.into_data().expect("data").chunk(), b"da");
            assert!(matches!(
                push.as_mut().poll(&mut task_cx),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(body.queued_bytes(), 2);
        }

        let second = poll_body(&mut body)
            .expect("second frame")
            .expect("valid second frame");
        assert_eq!(second.into_data().expect("data").chunk(), b"ta");
        assert_eq!(body.queued_bytes(), 0);
        assert_eq!(
            body.queued_bytes_peak(),
            2,
            "the producer-side high-water mark survives queue drain"
        );
    }

    #[test]
    fn incoming_body_queue_frame_peak_includes_send_waiting_behind_full_channel() {
        let cx = Cx::for_testing();
        let (writer, mut body) =
            IncomingRequestBody::channel_with_limits(&cx, BodyKind::ContentLength(4), 1, 8);
        let mut writer = writer.max_chunk_size(2);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        {
            let mut push = std::pin::pin!(writer.push_bytes(&cx, b"data"));
            assert!(matches!(push.as_mut().poll(&mut task_cx), Poll::Pending));
            assert_eq!(body.queued_frames(), 2);
            assert_eq!(body.queued_frames_peak(), 2);
            assert_eq!(body.queued_bytes(), 4);

            let first = poll_body(&mut body)
                .expect("first frame")
                .expect("valid first frame");
            assert_eq!(first.into_data().expect("data").chunk(), b"da");
            assert!(matches!(
                push.as_mut().poll(&mut task_cx),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(body.queued_frames(), 1);
        }

        let second = poll_body(&mut body)
            .expect("second frame")
            .expect("valid second frame");
        assert_eq!(second.into_data().expect("data").chunk(), b"ta");
        assert_eq!(body.queued_frames(), 0);
        assert_eq!(
            body.queued_frames_peak(),
            2,
            "producer-admission frame peak survives queue drain"
        );
    }

    #[test]
    fn incoming_body_queue_byte_wait_is_woken_by_cancellation() {
        let cx = Cx::for_testing();
        let (writer, body) =
            IncomingRequestBody::channel_with_limits(&cx, BodyKind::ContentLength(4), 8, 2);
        let mut writer = writer.max_chunk_size(2);
        let wake_count = Arc::new(AtomicUsize::new(0));
        let reserve_waker = counting_waker(Arc::clone(&wake_count));
        let mut task_cx = Context::from_waker(&reserve_waker);

        let mut push = std::pin::pin!(writer.push_bytes(&cx, b"data"));
        assert!(matches!(push.as_mut().poll(&mut task_cx), Poll::Pending));
        assert_eq!(body.queued_bytes(), 2, "first frame holds the byte cap");

        cx.cancel_fast(CancelKind::Deadline);
        assert_eq!(
            wake_count.load(Ordering::SeqCst),
            1,
            "context cancellation must wake the byte-budget waiter"
        );
        assert!(matches!(
            push.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(IncomingBodyError::Cancelled {
                kind: CancelKind::Deadline,
            }))
        ));
    }

    #[test]
    fn incoming_body_consumer_drop_drains_and_preserves_pipeline_remainder() {
        let cx = Cx::for_testing();
        let (mut writer, body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(5));
        drop(body);

        assert!(writer.consumer_dropped());
        // br-asupersync-hw83se: push_bytes now RETAINS "hello" on a consumer
        // drop, so the follow-up discard supplies only the next pipelined
        // request — re-passing "hello" here would double-buffer it. (The exact
        // driver Path B — push then discard_bytes(&[]) — is covered by
        // incoming_body_consumer_drop_during_push_retains_bytes_for_empty_discard.)
        let error = block_on(writer.push_bytes(&cx, b"hello"))
            .expect_err("driver must observe early consumer drop");
        assert_eq!(error, IncomingBodyError::ConsumerDropped);

        let progress = writer
            .discard_bytes(b"GET /next HTTP/1.1\r\n")
            .expect("bounded discard keeps framing synchronized");
        assert_eq!(progress.frames, 1);
        assert_eq!(progress.bytes, 5);
        assert!(progress.synchronized_eof);
        assert_eq!(writer.take_remainder().as_ref(), b"GET /next HTTP/1.1\r\n");
    }

    #[test]
    fn incoming_body_consumer_drop_during_push_retains_bytes_for_empty_discard() {
        // br-asupersync-hw83se: reproduces the real driver's Path B. The driver
        // saw a live consumer, so it called `push_bytes` (not `discard_bytes`)
        // with the read chunk it had `mem::take`n from its buffer — the only
        // copy. If the consumer dropped during that call, `push_bytes` returns
        // ConsumerDropped and the driver follows up with `discard_bytes(&[])`
        // (the EMPTY slice — it already handed the bytes over). Recovery must
        // therefore come from what `push_bytes` retained. Before the fix it
        // retained nothing, so the body framing AND the start of the next
        // pipelined request were lost, desynchronizing the keep-alive stream.
        let cx = Cx::for_testing();
        let (mut writer, body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(5));
        drop(body);
        assert!(writer.consumer_dropped());

        // The driver's `input` carries this body's bytes plus the next request.
        let error = block_on(writer.push_bytes(&cx, b"helloGET /next HTTP/1.1\r\n"))
            .expect_err("driver must observe the consumer drop");
        assert_eq!(error, IncomingBodyError::ConsumerDropped);

        // Exactly what the driver does next: discard with the EMPTY slice.
        let progress = writer
            .discard_bytes(b"")
            .expect("retained bytes keep framing synchronized under an empty discard");
        assert_eq!(progress.frames, 1);
        assert_eq!(progress.bytes, 5);
        assert!(progress.synchronized_eof);
        assert_eq!(writer.take_remainder().as_ref(), b"GET /next HTTP/1.1\r\n");
    }

    #[test]
    fn incoming_body_consumer_drop_counts_exact_queued_frames() {
        let cx = Cx::for_testing();
        let (writer, body) =
            IncomingRequestBody::channel_with_limits(&cx, BodyKind::ContentLength(4), 8, 8);
        let mut writer = writer.max_chunk_size(2);

        block_on(writer.push_bytes(&cx, b"data")).expect("queue complete body");
        assert_eq!(body.queued_bytes(), 4);
        drop(body);

        let progress = writer.drain_progress();
        assert_eq!(progress.frames, 2);
        assert_eq!(progress.bytes, 4);
        assert!(progress.synchronized_eof);
    }

    #[test]
    fn chunked_encoder_simple() {
        let encoded_chunk = ChunkedEncoder::encode_chunk(b"hello");
        assert_eq!(encoded_chunk.as_ref(), b"5\r\nhello\r\n");
    }

    #[test]
    fn chunked_encoder_final_with_trailers() {
        let mut encoder = ChunkedEncoder::new();
        let mut trailers = HeaderMap::new();
        trailers.insert(
            crate::http::body::HeaderName::from_static("x-checksum"),
            crate::http::body::HeaderValue::from_static("abc123"),
        );

        let final_chunk = encoder.encode_final(Some(&trailers));
        let expected = b"0\r\nx-checksum: abc123\r\n\r\n";
        assert_eq!(final_chunk.as_ref(), expected);
    }

    #[test]
    fn chunked_encoder_skips_invalid_trailer_fields() {
        let mut encoder = ChunkedEncoder::new();
        let mut trailers = HeaderMap::new();
        trailers.insert(
            crate::http::body::HeaderName::from_static("x-safe"),
            crate::http::body::HeaderValue::from_static("ok"),
        );
        trailers.insert(
            crate::http::body::HeaderName::from_string("x-bad\r\ninjected: nope"),
            crate::http::body::HeaderValue::from_static("bad"),
        );
        trailers.insert(
            crate::http::body::HeaderName::from_static("x-bad-value"),
            crate::http::body::HeaderValue::from_bytes(b"oops\r\nInjected: nope"),
        );

        let final_chunk = encoder.encode_final(Some(&trailers));
        assert_eq!(final_chunk.as_ref(), b"0\r\nx-safe: ok\r\n\r\n");
    }

    #[test]
    fn outgoing_body_chunked_roundtrip() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, mut body) = OutgoingBody::channel(&cx, BodyKind::Chunked);

        block_on(sender.send_bytes(&cx, Bytes::from_static(b"hello"))).unwrap();
        block_on(sender.send_bytes(&cx, Bytes::from_static(b" world"))).unwrap();
        sender.finish(&cx).unwrap();

        let mut encoder = ChunkedEncoder::new();
        let mut out = BytesMut::new();

        while let Some(frame) = poll_body(&mut body) {
            let frame = frame.unwrap();
            encoder.encode_frame(frame, &mut out);
        }
        encoder.finalize(None, &mut out);

        assert_eq!(out.as_ref(), b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    }

    #[test]
    fn produced_h1_envelope_accepts_exact_frame_and_refuses_oversize() {
        let cx: Cx = Cx::for_testing();
        let limit = NonZeroUsize::new(4).unwrap();
        let (mut sender, mut body) = OutgoingBody::channel_with_capacity_and_max_frame_bytes(
            &cx,
            BodyKind::Chunked,
            2,
            limit,
        );

        assert_eq!(sender.max_frame_bytes(), Some(limit));
        block_on(sender.send_bytes(&cx, Bytes::from_static(b"four"))).unwrap();
        let error = block_on(sender.send_bytes(&cx, Bytes::from_static(b"12345")))
            .expect_err("max_frame_bytes + 1 must fail before channel admission");
        assert!(matches!(
            error,
            HttpError::BodyTooLargeDetailed {
                actual: 5,
                limit: 4
            }
        ));
        assert_eq!(sender.total_bytes(), 4);
        sender.finish(&cx).unwrap();

        let frame = poll_body(&mut body).expect("exact-boundary frame").unwrap();
        assert_eq!(frame.into_data().unwrap().chunk(), b"four");
        assert!(poll_body(&mut body).is_none());

        let response = Http1ProducedResponse::chunked_with_max_frame_bytes(
            NonZeroUsize::new(3).unwrap(),
            NonZeroUsize::new(7).unwrap(),
            200,
            "OK",
            |_cx, sender| async move { Ok(sender) },
        );
        assert_eq!(response.max_retained_data_bytes(), 35);
    }

    #[test]
    fn outgoing_body_content_length_roundtrip() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, mut body) = OutgoingBody::channel(&cx, BodyKind::ContentLength(11));

        let mut trailers = HeaderMap::new();
        trailers.append(
            HeaderName::from_static("x-checksum"),
            HeaderValue::from_static("forbidden"),
        );
        assert!(matches!(
            block_on(sender.send_trailers(&cx, trailers)),
            Err(HttpError::TrailersNotAllowed)
        ));

        block_on(sender.send_bytes(&cx, Bytes::from_static(b"hello"))).unwrap();
        block_on(sender.send_bytes(&cx, Bytes::from_static(b" world"))).unwrap();
        sender.finish(&cx).unwrap();

        let mut collected = Vec::new();
        while let Some(frame) = poll_body(&mut body) {
            let frame = frame.unwrap();
            let data = frame.into_data().unwrap();
            collected.extend_from_slice(data.chunk());
        }

        assert_eq!(collected, b"hello world");
    }

    #[test]
    fn outgoing_body_backpressure_blocks_until_recv() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, mut body) = OutgoingBody::channel_with_capacity(&cx, BodyKind::Chunked, 1);

        block_on(sender.send_bytes(&cx, Bytes::from_static(b"one"))).unwrap();

        let finished = Arc::new(AtomicBool::new(false));
        let finished_clone = Arc::clone(&finished);
        let cx_worker = cx.clone();

        let handle = std::thread::spawn(move || {
            block_on(sender.send_bytes(&cx_worker, Bytes::from_static(b"two"))).unwrap();
            sender.finish(&cx_worker).unwrap();
            finished_clone.store(true, Ordering::SeqCst);
        });

        for _ in 0..1_000 {
            std::thread::yield_now();
        }
        assert!(!finished.load(Ordering::SeqCst));

        let _ = poll_body(&mut body);

        for i in 0..10_000 {
            if finished.load(Ordering::SeqCst) {
                break;
            }
            if i % 100 == 99 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            } else {
                std::thread::yield_now();
            }
        }
        assert!(finished.load(Ordering::SeqCst));

        let _ = poll_body(&mut body);
        handle.join().expect("sender thread panicked");
    }

    #[test]
    fn outgoing_body_pending_poll_keeps_waker_registration() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, mut body) = OutgoingBody::channel(&cx, BodyKind::Chunked);

        let wake_count = Arc::new(AtomicUsize::new(0));
        let frame_waker = counting_waker(Arc::clone(&wake_count));
        let mut task_cx = Context::from_waker(&frame_waker);

        let first = Pin::new(&mut body).poll_frame(&mut task_cx);
        assert!(matches!(first, Poll::Pending));

        block_on(sender.send_bytes(&cx, Bytes::from_static(b"x"))).expect("send bytes");
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);

        let second = Pin::new(&mut body).poll_frame(&mut task_cx);
        let frame = match second {
            Poll::Ready(Some(Ok(frame))) => frame,
            _other => return, // Ignore in this test
        };
        let data = frame.into_data().expect("data frame");
        assert_eq!(data.chunk(), b"x");
    }

    #[test]
    fn outgoing_body_trailers_mark_end_stream_immediately() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, mut body) = OutgoingBody::channel(&cx, BodyKind::Chunked);

        let mut trailers = HeaderMap::new();
        trailers.insert(
            crate::http::body::HeaderName::from_static("x-end"),
            crate::http::body::HeaderValue::from_static("true"),
        );

        block_on(sender.send_trailers(&cx, trailers)).expect("send trailers");

        let frame = poll_body(&mut body)
            .expect("trailers frame")
            .expect("ok frame");
        assert!(frame.is_trailers(), "terminal frame must be trailers");
        assert!(
            body.is_end_stream(),
            "body should mark end-stream immediately after trailers"
        );
        assert!(
            poll_body(&mut body).is_none(),
            "next poll should complete stream"
        );
    }

    #[test]
    fn outgoing_body_rejects_forbidden_trailers_without_consuming_state() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, _body) = OutgoingBody::channel(&cx, BodyKind::Chunked);
        let mut trailers = HeaderMap::new();
        trailers.insert(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static("7"),
        );

        let error = block_on(sender.send_trailers(&cx, trailers))
            .expect_err("framing trailers must fail before enqueue");

        assert!(matches!(error, HttpError::BadHeader));
        assert!(!sender.is_finished());
        block_on(sender.send_bytes(&cx, Bytes::from_static(b"still-open")))
            .expect("rejected trailers must leave sender usable");
    }

    #[test]
    fn outgoing_body_rejects_non_utf8_trailers_without_consuming_state() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, _body) = OutgoingBody::channel(&cx, BodyKind::Chunked);
        let mut trailers = HeaderMap::new();
        trailers.insert(
            HeaderName::from_static("x-binary"),
            HeaderValue::from_bytes(&[0xff]),
        );

        let error = block_on(sender.send_trailers(&cx, trailers))
            .expect_err("unencodable trailers must fail before enqueue");

        assert!(matches!(error, HttpError::InvalidHeaderValue));
        assert!(!sender.is_finished());
        block_on(sender.send_bytes(&cx, Bytes::from_static(b"still-open")))
            .expect("rejected trailers must leave sender usable");
    }

    /// A producer can commit DATA and terminal trailers and then have its
    /// context cancelled before the transport drains them. The public
    /// `Body::poll_frame` view still reports the cancellation, while the HTTP/2
    /// drain delivers the committed frames in order and then ends
    /// (br-asupersync-bi2462.105).
    #[test]
    fn committed_frames_precede_producer_cancellation_in_the_transport_drain() {
        let mut task = Context::from_waker(Waker::noop());
        let commit = |cx: &Cx| {
            let (mut sender, body) = OutgoingBody::channel(cx, BodyKind::Chunked);
            block_on(sender.send_bytes(cx, Bytes::from_static(b"committed"))).expect("data");
            block_on(sender.send_trailers(cx, HeaderMap::new())).expect("trailers");
            body
        };

        let public_cx: Cx = Cx::for_testing();
        let mut public = commit(&public_cx);
        public_cx.cancel_fast(CancelKind::User);
        assert!(matches!(
            Pin::new(&mut public).poll_frame(&mut task),
            Poll::Ready(Some(Err(HttpError::BodyCancelled)))
        ));

        let drain_cx: Cx = Cx::for_testing();
        let mut drained = commit(&drain_cx);
        drain_cx.cancel_fast(CancelKind::User);
        match drained.poll_committed_frame(&mut task) {
            Poll::Ready(Some(Ok(frame))) => {
                let data = frame.into_data().expect("committed DATA first");
                assert_eq!(data.chunk(), b"committed");
            }
            other => panic!("committed DATA must precede cancellation: {other:?}"),
        }
        assert!(matches!(
            drained.poll_committed_frame(&mut task),
            Poll::Ready(Some(Ok(frame))) if frame.is_trailers()
        ));
        assert!(matches!(drained.poll_committed_frame(&mut task), Poll::Ready(None)));

        // With nothing committed, the drain reports the cancellation as before.
        let empty_cx: Cx = Cx::for_testing();
        let (_sender, mut empty) = OutgoingBody::channel(&empty_cx, BodyKind::Chunked);
        empty_cx.cancel_fast(CancelKind::User);
        assert!(matches!(
            empty.poll_committed_frame(&mut task),
            Poll::Ready(Some(Err(HttpError::BodyCancelled)))
        ));
    }

    #[test]
    fn frames_committed_after_an_observed_cancellation_drain_once_the_producer_returns() {
        let mut task = Context::from_waker(Waker::noop());
        let producer_cx: Cx = Cx::for_testing();
        let (mut sender, mut body) = OutgoingBody::channel(&producer_cx, BodyKind::Chunked);
        producer_cx.cancel_fast(CancelKind::User);
        // The transport reads before the producer's masked terminal commit.
        assert!(matches!(
            body.poll_committed_frame(&mut task),
            Poll::Ready(Some(Err(HttpError::BodyCancelled)))
        ));
        {
            let mut send = std::pin::pin!(sender.send_trailers(&producer_cx, HeaderMap::new()));
            assert!(matches!(
                producer_cx.masked(|| send.as_mut().poll(&mut task)),
                Poll::Ready(Ok(()))
            ));
        }
        drop(sender);
        // A live read has ended; once the producer returned, its queue drains.
        assert!(matches!(
            body.poll_committed_frame(&mut task),
            Poll::Ready(None)
        ));
        assert!(matches!(
            body.take_frame_after_producer_returned(),
            Some(Ok(frame)) if frame.is_trailers()
        ));
        assert!(body.take_frame_after_producer_returned().is_none());
        assert!(body.is_end_stream());
    }

    #[test]
    fn outgoing_body_send_cancelled() {
        let cx_base: Cx = Cx::for_testing();
        let (mut sender, _body) = OutgoingBody::channel(&cx_base, BodyKind::Chunked);
        let cx_cancel: Cx = Cx::for_testing();
        cx_cancel.cancel_fast(CancelKind::User);

        let err = block_on(sender.send_bytes(&cx_cancel, Bytes::from_static(b"hello")))
            .expect_err("send should be cancelled");
        assert!(matches!(err, HttpError::BodyCancelled));
    }

    #[test]
    fn outgoing_body_send_cancelled_does_not_consume_state() {
        let cx_base: Cx = Cx::for_testing();
        let (mut sender, _body) = OutgoingBody::channel(&cx_base, BodyKind::ContentLength(5));
        let cx_cancel: Cx = Cx::for_testing();
        cx_cancel.cancel_fast(CancelKind::User);

        let err = block_on(sender.send_bytes(&cx_cancel, Bytes::from_static(b"hi")))
            .expect_err("send should be cancelled");
        assert!(matches!(err, HttpError::BodyCancelled));
        assert_eq!(sender.remaining, 5);
        assert_eq!(sender.total_bytes, 0);
        assert!(!sender.finished);
    }

    #[test]
    fn outgoing_body_send_trailers_cancelled_does_not_finish_sender() {
        let cx_base: Cx = Cx::for_testing();
        let (mut sender, _body) = OutgoingBody::channel(&cx_base, BodyKind::Chunked);
        let cx_cancel: Cx = Cx::for_testing();
        cx_cancel.cancel_fast(CancelKind::User);

        let err = block_on(sender.send_trailers(&cx_cancel, HeaderMap::new()))
            .expect_err("trailers send should be cancelled");
        assert!(matches!(err, HttpError::BodyCancelled));
        assert!(!sender.finished);
        assert!(sender.sender.is_some());

        block_on(sender.send_bytes(&cx_base, Bytes::from_static(b"ok")))
            .expect("sender should remain usable");
    }

    #[test]
    fn request_head_body_kind() {
        let head = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![("Content-Length".to_string(), "100".to_string())],
        };
        assert_eq!(head.body_kind(), BodyKind::ContentLength(100));

        let chunked_head = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![("Transfer-Encoding".to_string(), "chunked".to_string())],
        };
        assert_eq!(chunked_head.body_kind(), BodyKind::Chunked);

        let empty_head = RequestHead {
            method: super::super::types::Method::Get,
            uri: "/".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![],
        };
        assert_eq!(empty_head.body_kind(), BodyKind::Empty);
    }

    #[test]
    fn request_head_framing_uses_only_rfc_ows() {
        let ascii_ows = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![
                ("Content-Length".to_string(), "\t 5 \t".to_string()),
                ("Transfer-Encoding".to_string(), "\t chunked \t".to_string()),
            ],
        };
        assert_eq!(ascii_ows.content_length(), Some(5));
        assert!(ascii_ows.is_chunked());

        let unicode_whitespace = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![
                ("Content-Length".to_string(), "\u{a0}5\u{a0}".to_string()),
                (
                    "Transfer-Encoding".to_string(),
                    "\u{a0}chunked\u{a0}".to_string(),
                ),
            ],
        };
        assert_eq!(unicode_whitespace.content_length(), None);
        assert!(!unicode_whitespace.is_chunked());

        let signed_content_length = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![("Content-Length".to_string(), "+5".to_string())],
        };
        assert_eq!(signed_content_length.content_length(), None);

        let trailing_empty_coding = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![("Transfer-Encoding".to_string(), "chunked,".to_string())],
        };
        assert!(!trailing_empty_coding.is_chunked());
    }

    #[test]
    fn response_head_serialize() {
        let head = ResponseHead::new(200, "OK")
            .with_header("Content-Type", "text/plain")
            .with_header("Content-Length", "5");

        let serialized = head.serialize();
        let s = std::str::from_utf8(serialized.as_ref()).unwrap();

        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Type: text/plain\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn streaming_response_chunked() {
        let cx: Cx = Cx::for_testing();
        let (resp, _sender) = StreamingResponse::chunked(&cx, 4, 200, "OK");
        assert!(
            resp.head
                .headers
                .iter()
                .any(|(n, v)| { n.eq_ignore_ascii_case("transfer-encoding") && v == "chunked" })
        );
        assert!(resp.body.kind().is_chunked());
    }

    #[test]
    fn streaming_response_content_length() {
        let cx: Cx = Cx::for_testing();
        let (resp, _sender) = StreamingResponse::with_content_length(&cx, 4, 200, "OK", 100);
        assert!(
            resp.head
                .headers
                .iter()
                .any(|(n, v)| { n.eq_ignore_ascii_case("content-length") && v == "100" })
        );
        assert_eq!(resp.body.kind(), BodyKind::ContentLength(100));
    }

    #[test]
    fn body_kind_debug_clone_copy_eq() {
        let a = BodyKind::Chunked;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, BodyKind::Empty);
        assert_ne!(a, BodyKind::ContentLength(42));
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Chunked"));
    }

    #[test]
    fn request_head_debug_clone() {
        let head = RequestHead {
            method: super::super::types::Method::Get,
            uri: "/test".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
        };
        let cloned = head.clone();
        assert_eq!(cloned.uri, "/test");
        let dbg = format!("{head:?}");
        assert!(dbg.contains("RequestHead"));
    }

    #[test]
    fn response_head_debug_clone() {
        let head = ResponseHead::new(200, "OK");
        let cloned = head.clone();
        assert_eq!(cloned.status, 200);
        assert_eq!(cloned.reason, "OK");
        let dbg = format!("{head:?}");
        assert!(dbg.contains("ResponseHead"));
    }

    #[test]
    fn response_head_serialize_strips_crlf_from_reason() {
        let head = ResponseHead::new(200, "OK\r\nX-Injected: evil");
        let serialized = head.serialize();
        let text = String::from_utf8_lossy(&serialized);
        // The reason must not contain CRLF — injection attempt is neutralized.
        assert!(
            !text.contains("\r\nX-Injected"),
            "CRLF injection must be stripped from reason phrase: {text}"
        );
        assert!(text.starts_with("HTTP/1.1 200 OKX-Injected: evil\r\n"));
    }

    #[test]
    fn body_kind_te_plus_cl_uses_chunked() {
        let head = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![
                ("transfer-encoding".to_string(), "chunked".to_string()),
                ("content-length".to_string(), "42".to_string()),
            ],
        };
        // RFC 7230 §3.3.3: when both TE and CL are present, TE takes precedence.
        assert!(
            matches!(head.body_kind(), BodyKind::Chunked),
            "TE+CL should resolve to Chunked, not Empty"
        );
    }
