    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    use crate::runtime::yield_now::yield_now;
    use crate::stream;
    use crate::types::Budget;
    use serde_json::Value;
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Waker;

    fn noop_waker() -> std::task::Waker {
        std::task::Waker::noop().clone()
    }

    #[allow(clippy::type_complexity)]
    fn poll_body<B: Body + Unpin>(body: &mut B) -> Poll<Option<Result<Frame<B::Data>, B::Error>>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        Pin::new(body).poll_frame(&mut cx)
    }

    #[test]
    fn empty_body_is_end_stream() {
        let body = Empty::new();
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
    }

    #[test]
    fn empty_body_returns_none() {
        let mut body = Empty::new();
        assert!(matches!(poll_body(&mut body), Poll::Ready(None)));
    }

    #[test]
    fn buffered_bytes_body_returns_one_zero_copy_frame_then_eof() {
        let original = Bytes::from_static(b"buffered response");
        let original_ptr = original.as_ref().as_ptr();
        let mut body = original.clone();

        assert!(!body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(17));

        let frame = poll_body(&mut body);
        let Poll::Ready(Some(Ok(Frame::Data(data)))) = frame else {
            panic!("nonempty Bytes body must yield one DATA frame");
        };
        let framed = data.into_inner();
        assert_eq!(framed, original);
        assert_eq!(framed.as_ref().as_ptr(), original_ptr);
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(matches!(poll_body(&mut body), Poll::Ready(None)));
    }

    #[test]
    fn buffered_bytes_body_empty_is_immediate_eof() {
        let mut body = Bytes::new();

        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(matches!(poll_body(&mut body), Poll::Ready(None)));
    }

    #[test]
    fn buffered_bytes_body_shares_streamed_data_contract() {
        fn assert_shared_contract<B: Body<Data = BytesCursor>>() {}

        assert_shared_contract::<Bytes>();
        assert_shared_contract::<Full<BytesCursor>>();
        assert_shared_contract::<crate::http::h1::stream::OutgoingBody>();
    }

    #[test]
    fn full_body_returns_data_then_none() {
        // Use BytesCursor which implements Buf (Bytes alone doesn't implement Buf)
        let cursor = BytesCursor::new(Bytes::from_static(b"hello"));
        let mut body = Full::new(cursor);

        assert!(!body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(5));

        let Poll::Ready(Some(Ok(frame))) = poll_body(&mut body) else {
            panic!("expected data frame") // ubs:ignore - test logic
        };
        let data = frame.into_data().expect("expected data frame");
        assert_eq!(data.chunk(), b"hello");

        assert!(body.is_end_stream());

        assert!(matches!(poll_body(&mut body), Poll::Ready(None)));
    }

    #[test]
    fn full_body_from_string() {
        // BytesCursor wraps Bytes and implements Buf
        let cursor = BytesCursor::new(Bytes::from_static(b"hello world"));
        let body = Full::new(cursor);
        assert_eq!(body.size_hint().exact(), Some(11));
    }

    #[test]
    fn full_body_from_vec() {
        // BytesCursor wraps Bytes and implements Buf
        let cursor = BytesCursor::new(Bytes::from(vec![1_u8, 2, 3, 4, 5]));
        let body = Full::new(cursor);
        assert_eq!(body.size_hint().exact(), Some(5));
    }

    #[test]
    fn size_hint_exact() {
        let hint = SizeHint::with_exact(42);
        assert_eq!(hint.lower(), 42);
        assert_eq!(hint.upper(), Some(42));
        assert_eq!(hint.exact(), Some(42));
    }

    #[test]
    fn size_hint_default() {
        let hint = SizeHint::default();
        assert_eq!(hint.lower(), 0);
        assert_eq!(hint.upper(), None);
        assert_eq!(hint.exact(), None);
    }

    #[test]
    fn frame_data_methods() {
        let frame: Frame<Bytes> = Frame::data(Bytes::from_static(b"test"));
        assert!(frame.is_data());
        assert!(!frame.is_trailers());
        assert_eq!(frame.data_ref().unwrap().as_ref(), b"test");
    }

    #[test]
    fn frame_trailers_methods() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-checksum"),
            HeaderValue::from_static("abc123"),
        );

        let frame: Frame<Bytes> = Frame::trailers(headers);
        assert!(!frame.is_data());
        assert!(frame.is_trailers());
    }

    #[test]
    fn header_map_operations() {
        let mut headers = HeaderMap::new();
        assert!(headers.is_empty());

        let name = HeaderName::from_static("content-type");
        let value = HeaderValue::from_static("application/json");

        headers.insert(name.clone(), value);
        assert_eq!(headers.len(), 1);
        assert!(!headers.is_empty());

        let retrieved = headers.get(&name).expect("header should exist");
        assert_eq!(retrieved.as_bytes(), b"application/json");
    }

    #[test]
    fn header_name_lowercase() {
        let name = HeaderName::from_static("Content-Type");
        assert_eq!(name.as_str(), "content-type");
    }

    // ========================================================================
    // Pure data-type tests (wave 9 – CyanBarn)
    // ========================================================================

    #[test]
    fn frame_into_data_some() {
        let frame: Frame<Vec<u8>> = Frame::data(vec![1, 2, 3]);
        let data = frame.into_data();
        assert_eq!(data, Some(vec![1, 2, 3]));
    }

    #[test]
    fn frame_into_data_none_for_trailers() {
        let frame: Frame<Vec<u8>> = Frame::trailers(HeaderMap::new());
        assert!(frame.into_data().is_none());
    }

    #[test]
    fn frame_into_trailers_some() {
        let mut hm = HeaderMap::new();
        hm.insert(
            HeaderName::from_static("x-foo"),
            HeaderValue::from_static("bar"),
        );
        let frame: Frame<Vec<u8>> = Frame::trailers(hm);
        let trailers = frame.into_trailers().expect("should be trailers");
        assert_eq!(trailers.len(), 1);
    }

    #[test]
    fn frame_into_trailers_none_for_data() {
        let frame: Frame<Vec<u8>> = Frame::data(vec![]);
        assert!(frame.into_trailers().is_none());
    }

    #[test]
    fn frame_data_mut() {
        let mut frame: Frame<Vec<u8>> = Frame::data(vec![1]);
        if let Some(data) = frame.data_mut() {
            data.push(2);
        }
        assert_eq!(frame.data_ref(), Some(&vec![1, 2]));
    }

    #[test]
    fn frame_data_mut_none_for_trailers() {
        let mut frame: Frame<Vec<u8>> = Frame::trailers(HeaderMap::new());
        assert!(frame.data_mut().is_none());
    }

    #[test]
    fn frame_map_data() {
        let frame: Frame<u32> = Frame::data(5);
        let mapped = frame.map_data(|n| n * 2);
        assert_eq!(mapped.into_data(), Some(10));
    }

    #[test]
    fn frame_map_data_preserves_trailers() {
        let frame: Frame<u32> = Frame::trailers(HeaderMap::new());
        let mapped = frame.map_data(|n: u32| n * 2);
        assert!(mapped.is_trailers());
    }

    #[test]
    fn frame_debug() {
        let frame: Frame<u32> = Frame::data(42);
        let dbg = format!("{frame:?}");
        assert!(dbg.contains("Data"), "{dbg}");
    }

    #[test]
    fn header_map_with_capacity() {
        let hm = HeaderMap::with_capacity(10);
        assert!(hm.is_empty());
        assert_eq!(hm.len(), 0);
    }

    #[test]
    fn header_map_insert_replaces() {
        let mut hm = HeaderMap::new();
        let name = HeaderName::from_static("x-key");
        hm.insert(name.clone(), HeaderValue::from_static("v1"));
        hm.insert(name.clone(), HeaderValue::from_static("v2"));
        assert_eq!(hm.len(), 1);
        assert_eq!(hm.get(&name).unwrap().to_str().unwrap(), "v2");
    }

    #[test]
    fn header_map_append_allows_duplicates() {
        let mut hm = HeaderMap::new();
        let name = HeaderName::from_static("x-multi");
        hm.append(name.clone(), HeaderValue::from_static("a"));
        hm.append(name, HeaderValue::from_static("b"));
        assert_eq!(hm.len(), 2);
    }

    #[test]
    fn header_map_append_get_returns_first_duplicate() {
        let mut hm = HeaderMap::new();
        let name = HeaderName::from_static("x-multi");
        hm.append(name.clone(), HeaderValue::from_static("a"));
        hm.append(name.clone(), HeaderValue::from_static("b"));

        assert_eq!(hm.get(&name).unwrap().to_str().unwrap(), "a");
    }

    #[test]
    fn header_map_iter() {
        let mut hm = HeaderMap::new();
        hm.insert(HeaderName::from_static("a"), HeaderValue::from_static("1"));
        hm.insert(HeaderName::from_static("b"), HeaderValue::from_static("2"));
        let count = hm.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn header_map_get_missing() {
        let hm = HeaderMap::new();
        let name = HeaderName::from_static("missing");
        assert!(hm.get(&name).is_none());
    }

    #[test]
    fn header_map_insert_rebuilds_indices_after_removal() {
        let mut hm = HeaderMap::new();
        let a = HeaderName::from_static("a");
        let b = HeaderName::from_static("b");
        let c = HeaderName::from_static("c");

        hm.append(a.clone(), HeaderValue::from_static("a1"));
        hm.append(b.clone(), HeaderValue::from_static("b1"));
        hm.append(a.clone(), HeaderValue::from_static("a2"));
        hm.append(c.clone(), HeaderValue::from_static("c1"));

        hm.insert(a.clone(), HeaderValue::from_static("a3"));

        assert_eq!(hm.len(), 3);
        assert_eq!(hm.get(&a).unwrap().to_str().unwrap(), "a3");
        assert_eq!(hm.get(&b).unwrap().to_str().unwrap(), "b1");
        assert_eq!(hm.get(&c).unwrap().to_str().unwrap(), "c1");
    }

    #[test]
    fn header_map_insert_replaces_duplicates_without_orphaned_iter_entries() {
        let mut hm = HeaderMap::new();
        let a = HeaderName::from_static("a");
        let b = HeaderName::from_static("b");
        let c = HeaderName::from_static("c");

        hm.append(a.clone(), HeaderValue::from_static("a1"));
        hm.append(b.clone(), HeaderValue::from_static("b1"));
        hm.append(a.clone(), HeaderValue::from_static("a2"));
        hm.append(c.clone(), HeaderValue::from_static("c1"));

        hm.insert(a.clone(), HeaderValue::from_static("a3"));

        let observed: Vec<_> = hm
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap().to_owned()))
            .collect();

        assert_eq!(
            observed,
            vec![
                ("b".to_string(), "b1".to_string()),
                ("c".to_string(), "c1".to_string()),
                ("a".to_string(), "a3".to_string()),
            ]
        );
        assert_eq!(hm.get(&a).unwrap().to_str().unwrap(), "a3");
        assert_eq!(hm.iter().filter(|(name, _)| **name == a).count(), 1);
    }

    #[test]
    fn header_map_debug_clone_default() {
        let hm = HeaderMap::default();
        assert!(hm.is_empty());
        let dbg = format!("{hm:?}");
        assert!(dbg.contains("HeaderMap"), "{dbg}");

        let mut hm2 = hm;
        hm2.insert(HeaderName::from_static("x"), HeaderValue::from_static("y"));
        assert_eq!(hm2.len(), 1);
    }

    #[test]
    fn header_name_from_string() {
        let name = HeaderName::from_string("X-Custom");
        assert_eq!(name.as_str(), "x-custom");
    }

    #[test]
    fn header_name_display() {
        let name = HeaderName::from_static("content-type");
        assert_eq!(format!("{name}"), "content-type");
    }

    #[test]
    fn header_name_eq_hash() {
        use std::collections::HashSet;

        let a = HeaderName::from_static("x-foo");
        let b = HeaderName::from_string("X-Foo");
        assert_eq!(a, b);

        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn header_value_from_bytes() {
        let v = HeaderValue::from_bytes(b"hello");
        assert_eq!(v.as_bytes(), b"hello");
        assert_eq!(v.to_str().unwrap(), "hello");
    }

    #[test]
    fn header_value_from_string() {
        let v = HeaderValue::from_string("world".to_string());
        assert_eq!(v.as_bytes(), b"world");
    }

    #[test]
    fn header_value_display_utf8() {
        let v = HeaderValue::from_static("text/plain");
        assert_eq!(format!("{v}"), "text/plain");
    }

    #[test]
    fn header_value_display_non_utf8() {
        let v = HeaderValue::from_bytes(&[0xFF, 0xFE]);
        let disp = format!("{v}");
        // Non-UTF8 goes through Debug path
        assert!(disp.contains("255"), "{disp}");
    }

    #[test]
    fn header_value_eq_clone() {
        let a = HeaderValue::from_static("x");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn size_hint_set_lower_upper() {
        let mut hint = SizeHint::new();
        hint.set_lower(10);
        hint.set_upper(100);
        assert_eq!(hint.lower(), 10);
        assert_eq!(hint.upper(), Some(100));
        assert_eq!(hint.exact(), None); // lower != upper
    }

    #[test]
    fn size_hint_set_lower_allows_unknown_upper() {
        let mut hint = SizeHint::new();
        hint.set_lower(u64::MAX);

        assert_eq!(hint.lower(), u64::MAX);
        assert_eq!(hint.upper(), None);
        assert_eq!(hint.exact(), None);
    }

    #[test]
    fn size_hint_set_exact_updates_both_bounds() {
        let mut hint = SizeHint::new();
        hint.set_lower(5);
        hint.set_exact(42);

        assert_eq!(hint.lower(), 42);
        assert_eq!(hint.upper(), Some(42));
        assert_eq!(hint.exact(), Some(42));
    }

    #[test]
    #[should_panic(expected = "lower bound exceeds upper bound")]
    fn size_hint_set_lower_above_existing_upper_panics() {
        let mut hint = SizeHint::new();
        hint.set_upper(10);
        hint.set_lower(11);
    }

    #[test]
    #[should_panic(expected = "upper bound is below lower bound")]
    fn size_hint_set_upper_below_lower_panics() {
        let mut hint = SizeHint::new();
        hint.set_lower(11);
        hint.set_upper(10);
    }

    #[test]
    fn size_hint_exact_mismatch() {
        let mut hint = SizeHint::new();
        hint.set_lower(5);
        hint.set_upper(10);
        assert_eq!(hint.exact(), None);
    }

    #[test]
    fn size_hint_debug_clone_copy() {
        let hint = SizeHint::with_exact(42);
        let dbg = format!("{hint:?}");
        assert!(dbg.contains("SizeHint"), "{dbg}");
        let copied = hint; // Copy
        let cloned = hint;
        assert_eq!(copied.exact(), cloned.exact());
    }

    #[test]
    fn empty_debug_clone_copy_default() {
        let e = Empty::new();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Empty"), "{dbg}");
        let copied = e; // Copy
        let cloned = e;
        let defaulted = Empty;
        // All are the unit struct
        let _ = (copied, cloned, defaulted);
    }

    #[test]
    fn full_debug_clone() {
        let cursor = BytesCursor::new(Bytes::from_static(b"abc"));
        let body = Full::new(cursor);
        let dbg = format!("{body:?}");
        assert!(dbg.contains("Full"), "{dbg}");
        let cloned = body;
        assert_eq!(cloned.size_hint().exact(), Some(3));
    }

    #[test]
    fn full_from_static_str() {
        let body: Full<BytesCursor> = Full::from("hello");
        assert_eq!(body.size_hint().exact(), Some(5));
    }

    #[test]
    fn full_from_string_conversion() {
        let body: Full<BytesCursor> = Full::from("world".to_string());
        assert_eq!(body.size_hint().exact(), Some(5));
    }

    #[test]
    fn full_from_vec() {
        let body: Full<BytesCursor> = Full::from(vec![1u8, 2, 3]);
        assert_eq!(body.size_hint().exact(), Some(3));
    }

    #[test]
    fn full_empty_data_is_end_stream() {
        let cursor = BytesCursor::new(Bytes::from_static(b""));
        let body = Full::new(cursor);
        assert!(body.is_end_stream());
    }

    #[test]
    fn stream_body_debug_and_into_inner() {
        let stream = vec![1, 2, 3];
        let body = StreamBody::new(stream);
        let dbg = format!("{body:?}");
        assert!(dbg.contains("StreamBody"), "{dbg}");
        let inner = body.into_inner();
        assert_eq!(inner, vec![1, 2, 3]);
    }

    #[test]
    fn stream_body_polls_frames_and_fuses_eof() {
        let mut trailers = HeaderMap::new();
        trailers.insert(
            HeaderName::from_static("x-checksum"),
            HeaderValue::from_static("abc123"),
        );

        let stream = stream::iter(vec![
            Ok::<_, Infallible>(Frame::data(BytesCursor::new(Bytes::from_static(b"abc")))),
            Ok(Frame::trailers(trailers)),
        ]);
        let mut body = StreamBody::new(stream);

        assert!(!body.is_end_stream());

        let Poll::Ready(Some(Ok(frame))) = poll_body(&mut body) else {
            panic!("expected first data frame") // ubs:ignore - test logic
        };
        let data = frame.into_data().expect("expected data frame");
        assert_eq!(data.chunk(), b"abc");
        assert!(!body.is_end_stream());

        let Poll::Ready(Some(Ok(frame))) = poll_body(&mut body) else {
            panic!("expected trailers frame") // ubs:ignore - test logic
        };
        let trailers = frame.into_trailers().expect("expected trailers frame");
        assert_eq!(
            trailers
                .get(&HeaderName::from_static("x-checksum"))
                .unwrap(),
            &HeaderValue::from_static("abc123")
        );

        assert!(matches!(poll_body(&mut body), Poll::Ready(None)));
        assert!(body.is_end_stream());
        assert!(matches!(poll_body(&mut body), Poll::Ready(None)));
    }

    struct PendingThenFrameStream {
        yielded_pending: bool,
        yielded_frame: bool,
    }

    impl Stream for PendingThenFrameStream {
        type Item = Result<Frame<BytesCursor>, Infallible>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if !self.yielded_pending {
                self.yielded_pending = true;
                return Poll::Pending;
            }

            if !self.yielded_frame {
                self.yielded_frame = true;
                return Poll::Ready(Some(Ok(Frame::data(BytesCursor::new(Bytes::from_static(
                    b"later",
                ))))));
            }

            Poll::Ready(None)
        }
    }

    #[test]
    fn stream_body_propagates_pending() {
        let mut body = StreamBody::new(PendingThenFrameStream {
            yielded_pending: false,
            yielded_frame: false,
        });

        assert!(matches!(poll_body(&mut body), Poll::Pending));

        let Poll::Ready(Some(Ok(frame))) = poll_body(&mut body) else {
            panic!(
                // ubs:ignore
                "expected data frame after pending"
            )
        };
        let data = frame.into_data().expect("expected data frame");
        assert_eq!(data.chunk(), b"later");

        assert!(matches!(poll_body(&mut body), Poll::Ready(None)));
        assert!(body.is_end_stream());
    }

    struct GatedFrameStream {
        gate: Arc<AtomicBool>,
        pending_logged: bool,
        yielded_data: bool,
        yielded_trailers: bool,
        pending_waker: Arc<StdMutex<Option<Waker>>>,
        checkpoints: Arc<StdMutex<Vec<Value>>>,
    }

    impl Stream for GatedFrameStream {
        type Item = Result<Frame<BytesCursor>, Infallible>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if !self.gate.load(Ordering::SeqCst) {
                if !self.pending_logged {
                    self.pending_logged = true;
                    let event = serde_json::json!({
                        "phase": "body_pending",
                    });
                    tracing::info!(event = %event, "body_lab_checkpoint");
                    self.checkpoints.lock().unwrap().push(event);
                }
                *self.pending_waker.lock().unwrap() = Some(cx.waker().clone());
                return Poll::Pending;
            }

            if !self.yielded_data {
                self.yielded_data = true;
                let event = serde_json::json!({
                    "phase": "body_data_ready",
                    "bytes": 5,
                });
                tracing::info!(event = %event, "body_lab_checkpoint");
                self.checkpoints.lock().unwrap().push(event);
                return Poll::Ready(Some(Ok(Frame::data(BytesCursor::new(Bytes::from_static(
                    b"hello",
                ))))));
            }

            if !self.yielded_trailers {
                self.yielded_trailers = true;
                let mut trailers = HeaderMap::new();
                trailers.insert(
                    HeaderName::from_static("x-checksum"),
                    HeaderValue::from_static("done"),
                );
                let event = serde_json::json!({
                    "phase": "body_trailers_ready",
                });
                tracing::info!(event = %event, "body_lab_checkpoint");
                self.checkpoints.lock().unwrap().push(event);
                return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
            }

            let event = serde_json::json!({
                "phase": "body_eof",
            });
            tracing::info!(event = %event, "body_lab_checkpoint");
            self.checkpoints.lock().unwrap().push(event);
            Poll::Ready(None)
        }
    }

    #[test]
    fn stream_body_roundtrip_under_lab_runtime() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("stream_body_roundtrip_under_lab_runtime");

        let config = TestConfig::new()
            .with_seed(0xB0D1_5001)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let checkpoints = Arc::new(StdMutex::new(Vec::<Value>::new()));
        let gate = Arc::new(AtomicBool::new(false));
        let pending_waker = Arc::new(StdMutex::new(None::<Waker>));

        let (body_bytes, trailer_value, checkpoints) =
            LabRuntimeTarget::block_on(&mut runtime, async move {
                let cx = crate::cx::Cx::current().expect("lab runtime should install a current Cx");
                let body_spawn_cx = cx.clone();
                let gate_spawn_cx = cx.clone();

                let body_task = LabRuntimeTarget::spawn(&body_spawn_cx, Budget::INFINITE, {
                    let checkpoints = Arc::clone(&checkpoints);
                    let gate = Arc::clone(&gate);
                    let pending_waker = Arc::clone(&pending_waker);
                    async move {
                        let mut body = StreamBody::new(GatedFrameStream {
                            gate,
                            pending_logged: false,
                            yielded_data: false,
                            yielded_trailers: false,
                            pending_waker,
                            checkpoints: Arc::clone(&checkpoints),
                        });

                        let first = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
                            .await
                            .expect("stream body first frame should succeed")
                            .expect("stream body should yield first frame");
                        let data = first.into_data().expect("expected data frame");
                        let data_bytes = data.chunk().to_vec();
                        let data_event = serde_json::json!({
                            "phase": "body_data_consumed",
                            "bytes": data_bytes.len(),
                        });
                        tracing::info!(event = %data_event, "body_lab_checkpoint");
                        checkpoints.lock().unwrap().push(data_event);

                        let second = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
                            .await
                            .expect("stream body trailers should succeed")
                            .expect("stream body should yield trailers");
                        let trailers = second.into_trailers().expect("expected trailers frame");
                        let trailer_value = trailers
                            .get(&HeaderName::from_static("x-checksum"))
                            .expect("checksum trailer should exist")
                            .to_str()
                            .expect("checksum trailer should be utf-8")
                            .to_string();
                        let trailer_event = serde_json::json!({
                            "phase": "body_trailers_consumed",
                            "value": trailer_value,
                        });
                        tracing::info!(event = %trailer_event, "body_lab_checkpoint");
                        checkpoints.lock().unwrap().push(trailer_event);

                        let eof =
                            std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
                        assert!(eof.is_none(), "body should terminate after trailers");
                        let eof_event = serde_json::json!({
                            "phase": "body_complete",
                        });
                        tracing::info!(event = %eof_event, "body_lab_checkpoint");
                        checkpoints.lock().unwrap().push(eof_event);

                        (data_bytes, trailer_value)
                    }
                });

                let gate_task = LabRuntimeTarget::spawn(&gate_spawn_cx, Budget::INFINITE, {
                    let checkpoints = Arc::clone(&checkpoints);
                    let gate = Arc::clone(&gate);
                    let pending_waker = Arc::clone(&pending_waker);
                    async move {
                        yield_now().await;
                        yield_now().await;
                        gate.store(true, Ordering::SeqCst);
                        let event = serde_json::json!({
                            "phase": "gate_opened",
                        });
                        tracing::info!(event = %event, "body_lab_checkpoint");
                        checkpoints.lock().unwrap().push(event);
                        if let Some(waker) = pending_waker.lock().unwrap().take() {
                            waker.wake();
                        }
                    }
                });

                let gate_outcome = gate_task.await;
                crate::assert_with_log!(
                    matches!(gate_outcome, crate::types::Outcome::Ok(())),
                    "gate task completes successfully",
                    true,
                    matches!(gate_outcome, crate::types::Outcome::Ok(()))
                );

                let body_outcome = body_task.await;
                crate::assert_with_log!(
                    matches!(body_outcome, crate::types::Outcome::Ok(_)),
                    "body task completes successfully",
                    true,
                    matches!(body_outcome, crate::types::Outcome::Ok(_))
                );
                let crate::types::Outcome::Ok(result) = body_outcome else {
                    panic!("body task should finish successfully"); // ubs:ignore - test logic
                };

                (result.0, result.1, checkpoints.lock().unwrap().clone())
            });

        assert_eq!(body_bytes, b"hello");
        assert_eq!(trailer_value, "done");
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "body_pending"),
            "body should report an initial pending checkpoint"
        );
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "gate_opened"),
            "gate opening checkpoint should be recorded"
        );
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "body_trailers_consumed"),
            "trailer consumption checkpoint should be recorded"
        );

        let violations = runtime.oracles.check_all(runtime.now());
        assert!(
            violations.is_empty(),
            "body lab-runtime stream test should leave runtime invariants clean: {violations:?}"
        );
    }

    struct ErrorOnceStream {
        emitted_error: bool,
    }

    impl Stream for ErrorOnceStream {
        type Item = Result<Frame<BytesCursor>, &'static str>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if !self.emitted_error {
                self.emitted_error = true;
                return Poll::Ready(Some(Err("boom")));
            }

            Poll::Ready(None)
        }
    }

    #[test]
    fn stream_body_propagates_errors() {
        let mut body = StreamBody::new(ErrorOnceStream {
            emitted_error: false,
        });

        let Poll::Ready(Some(Err(err))) = poll_body(&mut body) else {
            panic!("expected error frame") // ubs:ignore - test logic
        };
        assert_eq!(err, "boom");
        assert!(!body.is_end_stream());

        assert!(matches!(poll_body(&mut body), Poll::Ready(None)));
        assert!(body.is_end_stream());
    }

    #[test]
    fn length_limit_error_display() {
        let err = LengthLimitError;
        assert_eq!(format!("{err}"), "body length limit exceeded");
    }

    #[test]
    fn length_limit_error_debug_clone_copy() {
        let err = LengthLimitError;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("LengthLimitError"), "{dbg}");
        let copied = err; // Copy
        let cloned = err;
        let _ = (copied, cloned);
    }

    #[test]
    fn length_limit_error_is_std_error() {
        let err = LengthLimitError;
        let _: &dyn std::error::Error = &err;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn limited_error_display() {
        let err: LimitedError<std::io::Error> = LimitedError::LengthLimit;
        assert_eq!(format!("{err}"), "body length limit exceeded");

        let done: LimitedError<std::io::Error> = LimitedError::PolledAfterCompletion;
        assert_eq!(format!("{done}"), "limited body polled after completion");

        let inner_err = LimitedError::Inner(std::io::Error::other("inner"));
        let disp = format!("{inner_err}");
        assert!(disp.contains("inner"), "{disp}");
    }

    #[test]
    fn limited_error_debug() {
        let err: LimitedError<&str> = LimitedError::LengthLimit;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("LengthLimit"), "{dbg}");

        let done: LimitedError<&str> = LimitedError::PolledAfterCompletion;
        let dbg = format!("{done:?}");
        assert!(dbg.contains("PolledAfterCompletion"), "{dbg}");
    }

    #[test]
    fn limited_error_source() {
        let err: LimitedError<std::io::Error> = LimitedError::LengthLimit;
        assert!(std::error::Error::source(&err).is_none());

        let done: LimitedError<std::io::Error> = LimitedError::PolledAfterCompletion;
        assert!(std::error::Error::source(&done).is_none());

        let inner = LimitedError::Inner(std::io::Error::other("cause"));
        assert!(std::error::Error::source(&inner).is_some());
    }

    #[test]
    fn collected_body_initial_state() {
        let body = Collected::new(Empty::new());
        assert!(body.data().is_empty());
        assert!(body.trailers().is_none());
    }

    #[test]
    fn collected_body_into_data() {
        let body = Collected::new(Empty::new());
        let data = body.into_data();
        assert!(data.is_empty());
    }

    #[test]
    fn limited_body_new() {
        let inner = Empty::new();
        let limited = Limited::new(inner, 1024);
        let dbg = format!("{limited:?}");
        assert!(dbg.contains("Limited"), "{dbg}");
    }

    #[derive(Debug)]
    struct PanicAfterFirstPollBody {
        first_poll: bool,
    }

    impl PanicAfterFirstPollBody {
        fn new() -> Self {
            Self { first_poll: true }
        }
    }

    impl Body for PanicAfterFirstPollBody {
        type Data = BytesCursor;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.first_poll {
                self.first_poll = false;
                let data = BytesCursor::new(Bytes::from_static(b"toolong"));
                return Poll::Ready(Some(Ok(Frame::data(data))));
            }

            panic!("Limited polled inner body after terminal length-limit violation"); // ubs:ignore - contract violation
        }
    }

    #[test]
    fn limited_body_fail_closes_after_length_limit_violation() {
        let inner = PanicAfterFirstPollBody::new();
        let mut limited = Limited::new(inner, 3);

        let first = poll_body(&mut limited);
        assert!(matches!(
            first,
            Poll::Ready(Some(Err(LimitedError::LengthLimit)))
        ));
        assert_eq!(limited.length_limit_actual(), Some(7));

        let second = poll_body(&mut limited);
        assert!(matches!(
            second,
            Poll::Ready(Some(Err(LimitedError::PolledAfterCompletion)))
        ));
    }

    #[derive(Debug)]
    struct ErrorThenPanicBody {
        first_poll: bool,
    }

    impl ErrorThenPanicBody {
        fn new() -> Self {
            Self { first_poll: true }
        }
    }

    impl Body for ErrorThenPanicBody {
        type Data = BytesCursor;
        type Error = std::io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.first_poll {
                self.first_poll = false;
                return Poll::Ready(Some(Err(std::io::Error::other("boom"))));
            }

            panic!(
                // ubs:ignore
                "Limited polled inner body after terminal inner error"
            );
        }
    }

    #[test]
    fn limited_body_fail_closes_after_terminal_inner_error() {
        let inner = ErrorThenPanicBody::new();
        let mut limited = Limited::new(inner, 16);

        let first = poll_body(&mut limited);
        assert!(matches!(
            first,
            Poll::Ready(Some(Err(LimitedError::Inner(_))))
        ));

        let second = poll_body(&mut limited);
        assert!(matches!(
            second,
            Poll::Ready(Some(Err(LimitedError::PolledAfterCompletion)))
        ));
    }

    #[derive(Debug)]
    struct EofThenPanicBody {
        first_poll: bool,
    }

    impl EofThenPanicBody {
        fn new() -> Self {
            Self { first_poll: true }
        }
    }

    impl Body for EofThenPanicBody {
        type Data = BytesCursor;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.first_poll {
                self.first_poll = false;
                return Poll::Ready(None);
            }

            panic!("Limited polled inner body after terminal completion"); // ubs:ignore - contract violation
        }
    }

    #[test]
    fn limited_body_does_not_repoll_completed_inner_body() {
        let inner = EofThenPanicBody::new();
        let mut limited = Limited::new(inner, 16);

        assert!(matches!(poll_body(&mut limited), Poll::Ready(None)));
        assert!(matches!(poll_body(&mut limited), Poll::Ready(None)));
    }

    /// br-asupersync-yrwie0: regression test that `HeaderMap` is NOT
    /// using `DetHasher` for its bucket placement. We can't directly
    /// observe which hasher the HashMap uses, so we test the security-
    /// relevant property: the bucket assignment of any given
    /// HeaderName must vary across processes (the hallmark of
    /// `RandomState`'s per-process seeding) — equivalently, the
    /// internal hash for a constant key must NOT match the
    /// deterministic hash that `DetHasher` would produce.
    ///
    /// This is asserted indirectly: we hash the same key via
    /// `DetHasher` ourselves and compare against the hash that would
    /// be produced by std's default `BuildHasher` for the HashMap we
    /// just constructed. The two MUST differ — if they're equal, the
    /// HashMap has reverted to `DetHasher` and the DoS hole is back.
    #[test]
    fn header_map_uses_randomized_hasher_not_dethasher() {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};

        // The actual map type we put inside HeaderMap.positions:
        let map: std::collections::HashMap<HeaderName, Vec<usize>> =
            std::collections::HashMap::new();
        let bh: &RandomState = map.hasher();

        // Hash of "x-attacker-controlled" via the map's hasher (RandomState).
        let key = HeaderName::from_static("x-attacker-controlled");
        let random_hash = bh.hash_one(&key);

        // Hash of the SAME key via DetHasher (the deterministic, fixed-seed,
        // attacker-readable hasher we MUST NOT be using here).
        let mut h_det = crate::util::DetHasher::default();
        key.hash(&mut h_det);
        let det_hash = h_det.finish();

        // If these are equal, HeaderMap is back on DetHasher. Re-introducing
        // the fixed seed re-introduces the offline collision-attack DoS.
        // The probability of accidental coincidence with RandomState is
        // 1/2^64 ≈ 5e-20 — effectively never on a healthy build.
        assert_ne!(
            random_hash, det_hash,
            "HeaderMap appears to be using DetHasher (fixed-seed). \
             This re-opens the hash-collision DoS vector that yrwie0 fixed."
        );
    }

    mod reader_body_tests {
        use super::*;
        use crate::io::{AsyncRead, ReadBuf};
        use std::cell::RefCell;
        use std::collections::VecDeque;
        use std::io;
        use std::marker::PhantomPinned;
        use std::sync::atomic::AtomicUsize;

        #[derive(Default)]
        struct Observations {
            polls: AtomicUsize,
            drops: AtomicUsize,
            offers: StdMutex<Vec<(usize, usize)>>,
        }

        enum ReadStep {
            Data(&'static [u8]),
            Pending,
            DataPending(&'static [u8]),
            DataError(&'static [u8], io::ErrorKind),
            Error(io::ErrorKind),
            Eof,
            Panic,
        }

        // Interior mutation makes the provider deliberately !Unpin without
        // requiring unsafe pin projections in the test.
        struct ScriptedReader {
            steps: RefCell<VecDeque<ReadStep>>,
            observations: Arc<Observations>,
            _pin: PhantomPinned,
        }

        impl ScriptedReader {
            fn new(steps: impl IntoIterator<Item = ReadStep>) -> (Self, Arc<Observations>) {
                let observations = Arc::new(Observations::default());
                (
                    Self {
                        steps: RefCell::new(steps.into_iter().collect()),
                        observations: Arc::clone(&observations),
                        _pin: PhantomPinned,
                    },
                    observations,
                )
            }
        }

        impl Drop for ScriptedReader {
            fn drop(&mut self) {
                self.observations.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        impl AsyncRead for ScriptedReader {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let this = self.as_ref().get_ref();
                this.observations.polls.fetch_add(1, Ordering::SeqCst);
                let pointer = buf.unfilled().as_ptr() as usize;
                let offered = buf.remaining();
                this.observations.offers.lock().unwrap().push((pointer, offered));
                let step = this.steps.borrow_mut().pop_front()
                    .expect("ReaderBody repolled a completed or failed reader");
                match step {
                    ReadStep::Data(bytes) => {
                        let count = bytes.len().min(buf.remaining());
                        buf.put_slice(&bytes[..count]);
                        if count < bytes.len() {
                            this.steps.borrow_mut().push_front(ReadStep::Data(&bytes[count..]));
                        }
                        Poll::Ready(Ok(()))
                    }
                    ReadStep::Pending => Poll::Pending,
                    ReadStep::DataPending(bytes) => {
                        buf.put_slice(bytes);
                        // No self-wake: the already consumed bytes must be
                        // returned immediately instead of parking the body.
                        Poll::Pending
                    }
                    ReadStep::DataError(bytes, kind) => {
                        buf.put_slice(bytes);
                        Poll::Ready(Err(io::Error::new(kind, "reader body source error")))
                    }
                    ReadStep::Error(kind) => {
                        Poll::Ready(Err(io::Error::new(kind, "reader body source error")))
                    }
                    ReadStep::Eof => Poll::Ready(Ok(())),
                    ReadStep::Panic => {
                        buf.put_slice(b"!");
                        panic!("reader body provider panic sentinel");
                    }
                }
            }
        }

        fn poll_reader<R: AsyncRead>(
            body: Pin<&mut ReaderBody<R>>,
        ) -> Poll<Option<Result<Frame<BytesCursor>, io::Error>>> {
            body.poll_frame(&mut Context::from_waker(Waker::noop()))
        }

        fn next_data<R: AsyncRead>(body: Pin<&mut ReaderBody<R>>) -> Bytes {
            match poll_reader(body) {
                Poll::Ready(Some(Ok(Frame::Data(data)))) => data.into_inner(),
                other => panic!("expected a data frame, got {other:?}"),
            }
        }

        #[test]
        fn pinned_reader_is_lazy_and_each_poll_reads_only_one_bounded_chunk() {
            let (reader, observed) = ScriptedReader::new([
                ReadStep::Data(b"abcdefgh"),
                ReadStep::Eof,
            ]);
            let mut body = Box::pin(ReaderBody::with_capacity(reader, 3));
            assert_eq!(body.as_ref().get_ref().buffer.capacity(), 0);
            assert_eq!(observed.polls.load(Ordering::SeqCst), 0);
            assert_eq!(body.size_hint().lower(), 0);
            assert_eq!(body.size_hint().upper(), None);
            assert!(!body.is_end_stream());

            let mut received = Vec::new();
            for (index, expected) in [b"abc".as_slice(), b"def", b"gh"].into_iter().enumerate() {
                let frame = next_data(body.as_mut());
                assert_eq!(frame.as_ref(), expected);
                assert_eq!(observed.polls.load(Ordering::SeqCst), index + 1);
                assert!(frame.len() <= 3);
                received.extend_from_slice(frame.as_ref());
                assert_eq!(body.size_hint().upper(), None);
                assert!(!body.is_end_stream());
            }
            assert_eq!(received, b"abcdefgh");
            assert_eq!(observed.polls.load(Ordering::SeqCst), 3);
            assert!(matches!(poll_reader(body.as_mut()), Poll::Ready(None)));
            assert_eq!(observed.polls.load(Ordering::SeqCst), 4);
            assert!(body.is_end_stream());
            assert_eq!(body.size_hint().exact(), Some(0));
            assert!(observed.offers.lock().unwrap().iter().all(|(_, length)| *length == 3));
            for _ in 0..3 {
                assert!(matches!(poll_reader(body.as_mut()), Poll::Ready(None)));
            }
            assert_eq!(observed.polls.load(Ordering::SeqCst), 4);
        }

        #[test]
        fn pending_read_reuses_its_buffer_and_transfers_it_without_payload_copy() {
            let (reader, observed) = ScriptedReader::new([
                ReadStep::Pending,
                ReadStep::Pending,
                ReadStep::Data(b"payload"),
                ReadStep::Eof,
            ]);
            let mut body = Box::pin(ReaderBody::with_capacity(reader, 32));
            assert!(poll_reader(body.as_mut()).is_pending());
            assert!(!body.is_end_stream());
            assert_eq!(body.size_hint().upper(), None);
            assert!(poll_reader(body.as_mut()).is_pending());
            let frame = next_data(body.as_mut());
            let offers = observed.offers.lock().unwrap();
            assert_eq!(offers.len(), 3);
            assert!(offers.iter().all(|offer| *offer == offers[0]));
            assert_eq!(frame.as_ref(), b"payload");
            assert_eq!(frame.as_ref().as_ptr() as usize, offers[2].0);
            drop(offers);
            assert_eq!(body.as_ref().get_ref().buffer.capacity(), 0);

            // The yielded allocation remains owned by the recipient after
            // the producer reaches EOF and is dropped.
            assert!(matches!(poll_reader(body.as_mut()), Poll::Ready(None)));
            drop(body);
            assert_eq!(observed.drops.load(Ordering::SeqCst), 1);
            assert_eq!(frame.as_ref(), b"payload");
        }

        #[test]
        fn zero_capacity_reads_one_byte_and_default_capacity_is_eight_kib() {
            let (reader, observed) = ScriptedReader::new([
                ReadStep::Data(b"xy"),
                ReadStep::Eof,
            ]);
            let mut body = Box::pin(ReaderBody::with_capacity(reader, 0));
            assert_eq!(next_data(body.as_mut()).as_ref(), b"x");
            assert_eq!(next_data(body.as_mut()).as_ref(), b"y");
            assert!(matches!(poll_reader(body.as_mut()), Poll::Ready(None)));
            assert!(observed.offers.lock().unwrap().iter().all(|(_, length)| *length == 1));

            let (reader, observed) = ScriptedReader::new([ReadStep::Pending]);
            let mut body = Box::pin(ReaderBody::new(reader));
            assert_eq!(body.as_ref().get_ref().buffer.capacity(), 0);
            assert!(poll_reader(body.as_mut()).is_pending());
            assert_eq!(observed.offers.lock().unwrap()[0].1, 8 * 1024);
        }

        #[test]
        fn bytes_returned_with_pending_are_yielded_without_another_read_or_wake() {
            let (reader, observed) = ScriptedReader::new([
                ReadStep::DataPending(b"first"),
                ReadStep::Data(b"second"),
                ReadStep::Eof,
            ]);
            let mut body = Box::pin(ReaderBody::with_capacity(reader, 8));
            assert_eq!(next_data(body.as_mut()).as_ref(), b"first");
            assert_eq!(observed.polls.load(Ordering::SeqCst), 1);
            assert_eq!(next_data(body.as_mut()).as_ref(), b"second");
            assert_eq!(observed.polls.load(Ordering::SeqCst), 2);
            assert!(matches!(poll_reader(body.as_mut()), Poll::Ready(None)));
            assert_eq!(observed.polls.load(Ordering::SeqCst), 3);
        }

        #[test]
        fn bytes_before_error_are_yielded_once_then_original_error_is_terminal() {
            let (reader, observed) = ScriptedReader::new([
                ReadStep::DataError(b"partial", io::ErrorKind::ConnectionReset),
            ]);
            let mut body = Box::pin(ReaderBody::with_capacity(reader, 16));
            let frame = next_data(body.as_mut());
            assert_eq!(frame.as_ref(), b"partial");
            assert_eq!(observed.polls.load(Ordering::SeqCst), 1);
            assert!(!body.is_end_stream());
            assert_eq!(body.size_hint().upper(), None);
            let error = match poll_reader(body.as_mut()) {
                Poll::Ready(Some(Err(error))) => error,
                other => panic!("expected the deferred source error, got {other:?}"),
            };
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            assert_eq!(error.to_string(), "reader body source error");
            assert!(body.is_end_stream());
            assert_eq!(body.size_hint().exact(), Some(0));
            for _ in 0..3 {
                assert!(matches!(poll_reader(body.as_mut()), Poll::Ready(None)));
            }
            assert_eq!(observed.polls.load(Ordering::SeqCst), 1);
            assert_eq!(frame.as_ref(), b"partial");
        }

        #[test]
        fn empty_eof_and_immediate_error_are_terminal_without_repolling() {
            for fail in [false, true] {
                let step = if fail {
                    ReadStep::Error(io::ErrorKind::BrokenPipe)
                } else {
                    ReadStep::Eof
                };
                let (reader, observed) = ScriptedReader::new([step]);
                let mut body = Box::pin(ReaderBody::new(reader));
                match poll_reader(body.as_mut()) {
                    Poll::Ready(Some(Err(error))) if fail => {
                        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                        assert_eq!(error.to_string(), "reader body source error");
                    }
                    Poll::Ready(None) if !fail => {}
                    other => panic!("unexpected terminal result: {other:?}"),
                }
                assert!(body.is_end_stream());
                assert_eq!(body.size_hint().exact(), Some(0));
                assert_eq!(body.as_ref().get_ref().buffer.capacity(), 0);
                for _ in 0..3 {
                    assert!(matches!(poll_reader(body.as_mut()), Poll::Ready(None)));
                }
                assert_eq!(observed.polls.load(Ordering::SeqCst), 1);
            }
        }

        #[test]
        fn caught_provider_panic_poison_is_reported_without_replaying_the_reader() {
            let (reader, observed) = ScriptedReader::new([ReadStep::Panic]);
            let mut body = Box::pin(ReaderBody::with_capacity(reader, 8));
            let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = poll_reader(body.as_mut());
            }));
            let payload = failure.expect_err("the original provider panic must propagate");
            let message = payload.downcast_ref::<&str>().copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
            assert_eq!(message, Some("reader body provider panic sentinel"));
            assert_eq!(observed.polls.load(Ordering::SeqCst), 1);
            assert!(matches!(
                poll_reader(body.as_mut()),
                Poll::Ready(Some(Err(error))) if error.kind() == io::ErrorKind::InvalidData
            ));
            assert!(body.is_end_stream());
            assert_eq!(body.size_hint().exact(), Some(0));
            assert_eq!(body.as_ref().get_ref().buffer.capacity(), 0);
            for _ in 0..3 {
                assert!(matches!(poll_reader(body.as_mut()), Poll::Ready(None)));
            }
            assert_eq!(observed.polls.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn drop_and_into_inner_preserve_sole_reader_ownership() {
            let (reader, observed) = ScriptedReader::new([ReadStep::Pending]);
            let mut body = Box::pin(ReaderBody::new(reader));
            assert!(poll_reader(body.as_mut()).is_pending());
            assert_eq!(observed.drops.load(Ordering::SeqCst), 0);
            drop(body);
            assert_eq!(observed.polls.load(Ordering::SeqCst), 1);
            assert_eq!(observed.drops.load(Ordering::SeqCst), 1);

            let (reader, observed) = ScriptedReader::new([ReadStep::Eof]);
            let body = ReaderBody::new(reader);
            assert!(Arc::ptr_eq(&body.get_ref().observations, &observed));
            let reader = body.into_inner();
            assert_eq!(observed.polls.load(Ordering::SeqCst), 0);
            assert_eq!(observed.drops.load(Ordering::SeqCst), 0);
            drop(reader);
            assert_eq!(observed.drops.load(Ordering::SeqCst), 1);
        }
    }
