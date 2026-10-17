    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::bytes::Buf;
    use crate::http::body::{Body, Frame};
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = std::pin::pin!(future);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn poll_body<B: Body + Unpin>(body: &mut B) -> Option<Result<Frame<B::Data>, B::Error>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        loop {
            match Pin::new(&mut *body).poll_frame(&mut cx) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn body_has_no_more_data_after_cancel<B>(frame: Option<Result<Frame<B>, HttpError>>) -> bool {
        matches!(frame, None | Some(Err(HttpError::BodyCancelled)))
    }

    // ================================================================
    // SseEvent serialization
    // ================================================================

    #[test]
    fn event_data_only() {
        let event = SseEvent::default().data("hello");
        assert_eq!(event.to_string(), "data:hello\n\n");
    }

    #[test]
    fn event_with_type() {
        let event = SseEvent::default().event("message").data("hello");
        assert_eq!(event.to_string(), "event:message\ndata:hello\n\n");
    }

    #[test]
    fn event_with_id() {
        let event = SseEvent::default().data("hello").id("42");
        assert_eq!(event.to_string(), "data:hello\nid:42\n\n");
    }

    #[test]
    fn event_with_retry() {
        let event = SseEvent::default().data("hello").retry(3000);
        assert_eq!(event.to_string(), "data:hello\nretry:3000\n\n");
    }

    #[test]
    fn event_with_retry_duration() {
        let event = SseEvent::default()
            .data("hello")
            .retry_duration(Duration::from_secs(5));
        assert_eq!(event.to_string(), "data:hello\nretry:5000\n\n");
    }

    #[test]
    fn event_with_comment() {
        let event = SseEvent::default().comment("keep-alive");
        assert_eq!(event.to_string(), ":keep-alive\n\n");
    }

    #[test]
    fn event_multiline_data() {
        let event = SseEvent::default().data("line1\nline2\nline3");
        assert_eq!(event.to_string(), "data:line1\ndata:line2\ndata:line3\n\n");
    }

    /// br-asupersync-fek81o — WHATWG HTML §9.2.6 EventSource parser
    /// strips one U+0020 SPACE from the start of every field value.
    /// Without compensation, `data(" hello")` would emit `data: hello`
    /// which the parser strips to `"hello"` — the application's
    /// leading space is silently lost. Pre-fix this test failed with
    /// `data: hello\n\n`. Post-fix the writer emits an extra padding
    /// space (`data:  hello`) so the parser's strip leaves the
    /// original ` hello` intact.
    #[test]
    fn event_data_preserves_leading_space_for_whatwg_round_trip() {
        let event = SseEvent::default().data(" hello");
        assert_eq!(
            event.to_string(),
            "data:  hello\n\n",
            "leading space in data must be padded so the WHATWG parser's \
             leading-space strip preserves the application value",
        );
    }

    /// Counter test: a line with NO leading space stays at the
    /// pre-fix wire format `data:value` (no extra space). Locks the
    /// fix to leading-space lines only so the existing wire-format
    /// test pins below stay green.
    #[test]
    fn event_data_without_leading_space_unchanged() {
        let event = SseEvent::default().data("hello");
        assert_eq!(event.to_string(), "data:hello\n\n");
    }

    /// br-asupersync-fek81o — multi-line data where ONLY some lines
    /// start with a space: each line is independently padded.
    #[test]
    fn event_data_multiline_pads_only_leading_space_lines() {
        let event = SseEvent::default().data("first\n  second\nthird");
        assert_eq!(
            event.to_string(),
            "data:first\ndata:   second\ndata:third\n\n",
            "only the leading-space line gets an extra padding space; \
             the parser will strip one and preserve the rest. Got: {:?}",
            event.to_string(),
        );
    }

    /// br-asupersync-fek81o — a tab-prefixed line is NOT padded
    /// (parser only strips U+0020 SPACE, not U+0009 HTAB).
    #[test]
    fn event_data_tab_prefix_not_padded() {
        let event = SseEvent::default().data("\tindented");
        assert_eq!(
            event.to_string(),
            "data:\tindented\n\n",
            "U+0009 HTAB is not stripped by the WHATWG parser; \
             only U+0020 SPACE needs the padding workaround",
        );
    }

    #[test]
    fn event_all_fields() {
        let event = SseEvent::default()
            .comment("ping")
            .event("update")
            .data("payload")
            .id("7")
            .retry(1000);
        assert_eq!(
            event.to_string(),
            ":ping\nevent:update\ndata:payload\nid:7\nretry:1000\n\n"
        );
    }

    #[test]
    fn event_id_rejects_null_bytes() {
        let event = SseEvent::default().data("hello").id("bad\0id");
        assert!(event.id.is_none(), "null bytes in ID should be rejected");
        assert_eq!(event.to_string(), "data:hello\n\n");
    }

    #[test]
    fn event_empty() {
        let event = SseEvent::default();
        assert_eq!(event.to_string(), "\n");
    }

    #[test]
    fn event_multiline_comment() {
        let event = SseEvent::default().comment("line1\nline2");
        assert_eq!(event.to_string(), ":line1\n:line2\n\n");
    }

    #[test]
    fn event_comment_normalizes_bare_cr_to_block_field_injection() {
        // A bare \r in a comment must be treated as a line break so the
        // browser's EventSource parser cannot interpret the second half as
        // a real `data:` / `event:` / `id:` field. Without normalization,
        // Rust's .lines() leaves the \r in place and the injected payload
        // appears verbatim in the wire format.
        let event = SseEvent::default().comment("safe\rdata: injected");
        let body = event.to_string();
        assert!(
            !body.contains('\r'),
            "comment normalization should remove bare CR; got: {body:?}"
        );
        // The injected payload, if present at all, must appear inside a
        // comment line (prefixed with `:`), never as a top-level data field.
        assert_eq!(body, ":safe\n:data: injected\n\n");
    }

    #[test]
    fn event_comment_normalizes_crlf() {
        // CRLF in a comment should produce two clean comment lines, not
        // a stray \r followed by a separate \n.
        let event = SseEvent::default().comment("first\r\nsecond");
        assert_eq!(event.to_string(), ":first\n:second\n\n");
    }

    // ================================================================
    // Sse response
    // ================================================================

    #[test]
    fn sse_empty() {
        let sse = Sse::empty();
        assert!(sse.is_empty());
        assert_eq!(sse.len(), 0);
        assert_eq!(sse.to_body(), "");
    }

    #[test]
    fn sse_single_event() {
        let sse = Sse::event(SseEvent::default().data("hello"));
        assert_eq!(sse.len(), 1);
        assert_eq!(sse.to_body(), "data:hello\n\n");
    }

    #[test]
    fn sse_multiple_events() {
        let sse = Sse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("second"),
        ]);
        assert_eq!(sse.to_body(), "data:first\n\ndata:second\n\n");
    }

    #[test]
    fn sse_keep_alive() {
        let sse = Sse::new(vec![SseEvent::default().data("hello")]).keep_alive();
        assert_eq!(sse.to_body(), ":keep-alive\n\ndata:hello\n\n");
    }

    #[test]
    fn sse_explicit_event_ids_drive_reconnection() {
        let sse = Sse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("last").id("99"),
        ]);
        let body = sse.to_body();
        // First event should not have an ID.
        assert!(body.starts_with("data:first\n\n"));
        // The server-authored last event ID should be present.
        assert!(body.contains("id:99"));
    }

    #[test]
    fn sse_explicit_event_id_is_preserved() {
        let sse = Sse::new(vec![SseEvent::default().data("event").id("existing")]);
        let body = sse.to_body();
        assert!(body.contains("id:existing"));
    }

    // ================================================================
    // IntoResponse
    // ================================================================

    #[test]
    fn sse_into_response_headers() {
        let sse = Sse::event(SseEvent::default().data("hello"));
        let resp = sse.into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/event-stream"
        );
        assert_eq!(resp.headers.get("cache-control").unwrap(), "no-cache");
        assert_eq!(resp.headers.get("connection").unwrap(), "keep-alive");
    }

    #[test]
    fn sse_into_response_body() {
        let sse = Sse::new(vec![
            SseEvent::default().event("msg").data("hello"),
            SseEvent::default().event("msg").data("world"),
        ]);
        let resp = sse.into_response();
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert_eq!(body, "event:msg\ndata:hello\n\nevent:msg\ndata:world\n\n");
    }

    #[test]
    fn sse_event_into_response() {
        let event = SseEvent::default().data("direct");
        let resp = event.into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/event-stream"
        );
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert_eq!(body, "data:direct\n\n");
    }

    #[test]
    fn sse_keep_alive_with_multiple_events() {
        let sse = Sse::new(vec![
            SseEvent::default().data("a"),
            SseEvent::default().data("b"),
            SseEvent::default().data("c"),
        ])
        .keep_alive();
        let body = sse.to_body();
        assert!(body.starts_with(":keep-alive\n\n"));
        assert_eq!(body, ":keep-alive\n\ndata:a\n\ndata:b\n\ndata:c\n\n");
    }

    // ================================================================
    // StreamingSse response state
    // ================================================================

    #[test]
    fn streaming_sse_emits_one_chunk_per_event_in_order() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![
            SseEvent::default().event("update").data("one").id("1"),
            SseEvent::default().event("update").data("two").id("2"),
        ]);

        let first = stream
            .next_chunk(&cx)
            .expect("first chunk")
            .expect("first event");
        let second = stream
            .next_chunk(&cx)
            .expect("second chunk")
            .expect("second event");
        let done = stream.next_chunk(&cx).expect("stream end");

        assert_eq!(
            std::str::from_utf8(&first).expect("utf8"),
            "event:update\ndata:one\nid:1\n\n"
        );
        assert_eq!(
            std::str::from_utf8(&second).expect("utf8"),
            "event:update\ndata:two\nid:2\n\n"
        );
        assert!(done.is_none());
        assert!(stream.is_closed());
        assert_eq!(stream.bytes_emitted(), first.len() + second.len());
    }

    #[test]
    fn streaming_sse_heartbeat_chunk_is_comment_without_advancing_events() {
        let cx = Cx::for_testing();
        let mut stream =
            StreamingSse::new(vec![SseEvent::default().data("payload")]).heartbeat_comment("tick");

        let heartbeat = stream.heartbeat_chunk(&cx).expect("heartbeat");
        let event = stream
            .next_chunk(&cx)
            .expect("event chunk")
            .expect("event present");

        assert_eq!(std::str::from_utf8(&heartbeat).expect("utf8"), ":tick\n\n");
        assert_eq!(
            std::str::from_utf8(&event).expect("utf8"),
            "data:payload\n\n"
        );
        assert_eq!(stream.bytes_emitted(), heartbeat.len() + event.len());
        assert_eq!(stream.event_bytes_emitted, event.len());
    }

    #[test]
    fn streaming_sse_heartbeats_do_not_consume_event_byte_budget() {
        let cx = Cx::for_testing();
        let first_wire = "data:one\n\n";
        let second_wire = "data:two\n\n";
        let mut stream = StreamingSse::new(vec![
            SseEvent::default().data("one"),
            SseEvent::default().data("two"),
        ])
        .heartbeat_comment("tick")
        .max_total_bytes(first_wire.len());

        let first_heartbeat = stream.heartbeat_chunk(&cx).expect("first heartbeat");
        let second_heartbeat = stream.heartbeat_chunk(&cx).expect("second heartbeat");
        let heartbeat_bytes = first_heartbeat.len() + second_heartbeat.len();
        assert_eq!(stream.bytes_emitted(), heartbeat_bytes);
        assert_eq!(stream.event_bytes_emitted, 0);

        let first_event = stream
            .next_chunk(&cx)
            .expect("first event serialization")
            .expect("first event present");
        assert_eq!(first_event, first_wire.as_bytes());
        assert_eq!(stream.event_bytes_emitted, first_wire.len());
        assert_eq!(stream.bytes_emitted(), heartbeat_bytes + first_wire.len());

        let error = stream
            .next_chunk(&cx)
            .expect_err("second event must exceed the event-only byte budget");
        assert_eq!(
            error,
            StreamingSseError::TotalBytesExceeded {
                actual: first_wire.len() + second_wire.len(),
                max: first_wire.len(),
            }
        );
        assert_eq!(stream.event_bytes_emitted, first_wire.len());
        assert_eq!(stream.bytes_emitted(), heartbeat_bytes + first_wire.len());
    }

    #[test]
    fn streaming_sse_heartbeat_still_respects_per_chunk_cap() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![SseEvent::default().data("pending")])
            .heartbeat_comment("tick")
            .max_event_bytes(6);

        assert_eq!(
            stream.heartbeat_chunk(&cx),
            Err(StreamingSseError::EventTooLarge { actual: 7, max: 6 })
        );
        assert_eq!(stream.event_bytes_emitted, 0);
        assert_eq!(stream.bytes_emitted(), 0);
    }

    #[test]
    fn streaming_sse_rejects_oversized_event_chunk() {
        let cx = Cx::for_testing();
        let mut stream =
            StreamingSse::new(vec![SseEvent::default().data("abcdef")]).max_event_bytes(8);

        let err = stream.next_chunk(&cx).expect_err("event should exceed cap");
        assert!(matches!(
            err,
            StreamingSseError::EventTooLarge { actual, max: 8 } if actual > 8
        ));
        assert_eq!(stream.bytes_emitted(), 0);
    }

    #[test]
    fn streaming_sse_rejects_total_bytes_limit_without_partial_accounting() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![
            SseEvent::default().data("one"),
            SseEvent::default().data("two"),
        ])
        .max_total_bytes("data:one\n\n".len());

        let first = stream
            .next_chunk(&cx)
            .expect("first chunk")
            .expect("first event");
        let err = stream
            .next_chunk(&cx)
            .expect_err("second chunk should exceed total cap");

        assert_eq!(std::str::from_utf8(&first).expect("utf8"), "data:one\n\n");
        assert!(matches!(
            err,
            StreamingSseError::TotalBytesExceeded { actual, max }
                if actual > max && max == first.len()
        ));
        assert_eq!(stream.bytes_emitted(), first.len());
    }

    #[test]
    fn streaming_sse_cancellation_closes_source_before_next_emit() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("second"),
        ]);
        let _first = stream
            .next_chunk(&cx)
            .expect("first chunk")
            .expect("first event");

        cx.set_cancel_requested(true);
        let err = stream
            .next_chunk(&cx)
            .expect_err("cancelled stream should fail");

        assert_eq!(err, StreamingSseError::Cancelled);
        assert!(stream.is_closed());
        assert!(stream.next_chunk(&Cx::for_testing()).unwrap().is_none());
    }

    #[test]
    fn streaming_sse_disconnect_sets_request_cancellation() {
        let cx = Cx::for_testing();
        let region = crate::web::request_region::RequestRegion::new(
            &cx,
            crate::web::extract::Request::new("GET", "/events"),
        );

        let outcome = region.run(|ctx| {
            let mut stream = StreamingSse::new(vec![SseEvent::default().data("pending")]);
            stream.cancel_for_disconnect(ctx.cx());
            assert!(stream.is_closed());
            Response::empty(StatusCode::CLIENT_CLOSED_REQUEST)
        });

        assert!(
            cx.is_cancel_requested(),
            "client disconnect should mark the request Cx cancelled"
        );
        assert_eq!(
            outcome.into_response().status,
            StatusCode::CLIENT_CLOSED_REQUEST
        );
    }

    #[test]
    fn streaming_sse_propagates_source_error() {
        struct FailingSource;

        impl StreamingSseSource for FailingSource {
            fn next_event(&mut self, _cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError> {
                Err(StreamingSseError::Producer("synthetic failure".to_string()))
            }
        }

        let cx = Cx::for_testing();
        let mut stream = StreamingSse::from_source(FailingSource);
        let err = stream.next_chunk(&cx).expect_err("producer error");

        assert_eq!(
            err,
            StreamingSseError::Producer("synthetic failure".to_string())
        );
        assert!(!stream.is_closed());
    }

    #[test]
    fn streaming_sse_headers_match_event_stream_response_requirements() {
        assert_eq!(
            StreamingSse::<VecSseSource>::headers(),
            [
                ("content-type", "text/event-stream"),
                ("cache-control", "no-cache"),
                ("connection", "keep-alive"),
            ]
        );
    }

    #[test]
    fn streaming_sse_h1_response_head_is_chunked_event_stream() {
        let cx = Cx::for_testing();
        let stream = StreamingSse::new(vec![SseEvent::default().data("hello")]);
        let (response, sender) =
            stream.h1_chunked_response(&cx, DEFAULT_STREAMING_SSE_H1_CHANNEL_CAPACITY);

        let header = |name: &str| {
            response
                .head
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(response.head.status, StatusCode::OK.as_u16());
        assert_eq!(header("transfer-encoding"), Some("chunked"));
        assert_eq!(header("content-type"), Some("text/event-stream"));
        assert_eq!(header("cache-control"), Some("no-cache"));
        assert_eq!(header("connection"), Some("keep-alive"));
        assert!(sender.kind().is_chunked());
    }

    #[test]
    fn streaming_sse_h1_transport_sends_events_in_order_and_finishes() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("second"),
        ]);
        let (response, mut sender) = stream.h1_chunked_response(&cx, 2);
        let mut body = response.body;

        let first = block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("first send");
        assert_eq!(
            first,
            StreamingSseTransportStep::Sent {
                bytes: "data:first\n\n".len(),
                total_bytes: "data:first\n\n".len(),
            }
        );
        let first_frame = poll_body(&mut body)
            .expect("first frame")
            .expect("first frame ok");
        assert_eq!(
            first_frame.into_data().expect("data frame").chunk(),
            b"data:first\n\n"
        );

        let second = block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("second send");
        assert_eq!(
            second,
            StreamingSseTransportStep::Sent {
                bytes: "data:second\n\n".len(),
                total_bytes: "data:first\n\n".len() + "data:second\n\n".len(),
            }
        );
        let second_frame = poll_body(&mut body)
            .expect("second frame")
            .expect("second frame ok");
        assert_eq!(
            second_frame.into_data().expect("data frame").chunk(),
            b"data:second\n\n"
        );

        let complete =
            block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("complete send");
        assert_eq!(complete, StreamingSseTransportStep::Complete);
        assert!(sender.is_finished());
        assert!(poll_body(&mut body).is_none());
    }

    #[test]
    fn streaming_sse_h1_dropped_pending_event_retries_without_precommit() {
        let cx = Cx::for_testing();
        let first_wire = b"data:first\n\n";
        let second_wire = b"data:second\n\n";
        let mut stream = StreamingSse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("second"),
        ]);
        let (response, mut sender) = stream.h1_chunked_response(&cx, 1);
        let mut body = response.body;

        block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("first send");
        assert_eq!(stream.bytes_emitted(), first_wire.len());
        assert_eq!(sender.total_bytes(), first_wire.len() as u64);

        {
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut future = Box::pin(stream.send_next_h1_chunk(&cx, &mut sender));
            assert!(
                future.as_mut().poll(&mut task_cx).is_pending(),
                "a full H1 body channel must backpressure the second event"
            );
        }

        assert_eq!(stream.bytes_emitted(), first_wire.len());
        assert_eq!(stream.event_bytes_emitted, first_wire.len());
        assert_eq!(sender.total_bytes(), first_wire.len() as u64);
        assert_eq!(stream.source.remaining(), 0);
        assert_eq!(
            stream
                .pending_event_chunk
                .as_ref()
                .map(|pending| pending.bytes.as_slice()),
            Some(second_wire.as_slice())
        );

        let first_frame = poll_body(&mut body)
            .expect("first frame")
            .expect("first frame ok");
        assert_eq!(
            first_frame.into_data().expect("data frame").chunk(),
            first_wire
        );

        stream = stream
            .max_event_bytes(second_wire.len() - 1)
            .max_total_bytes(first_wire.len() + second_wire.len() - 1);
        let event_cap_error = block_on(stream.send_next_h1_chunk(&cx, &mut sender))
            .expect_err("lowered event cap must revalidate the pending event");
        assert!(matches!(
            event_cap_error,
            StreamingSseTransportError::Stream(StreamingSseError::EventTooLarge {
                actual,
                max,
            }) if actual == second_wire.len() && max == second_wire.len() - 1
        ));
        assert_eq!(stream.bytes_emitted(), first_wire.len());
        assert_eq!(sender.total_bytes(), first_wire.len() as u64);
        assert!(stream.pending_event_chunk.is_some());

        stream = stream.max_event_bytes(second_wire.len());
        let total_cap_error = block_on(stream.send_next_h1_chunk(&cx, &mut sender))
            .expect_err("lowered total cap must revalidate the pending event");
        assert!(matches!(
            total_cap_error,
            StreamingSseTransportError::Stream(StreamingSseError::TotalBytesExceeded {
                actual,
                max,
            }) if actual == first_wire.len() + second_wire.len()
                && max == first_wire.len() + second_wire.len() - 1
        ));
        assert_eq!(stream.bytes_emitted(), first_wire.len());
        assert_eq!(sender.total_bytes(), first_wire.len() as u64);
        assert!(stream.pending_event_chunk.is_some());

        stream = stream.max_total_bytes(first_wire.len() + second_wire.len());
        let retry = {
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut future = Box::pin(stream.send_next_h1_chunk(&cx, &mut sender));
            match future.as_mut().poll(&mut task_cx) {
                Poll::Ready(result) => result.expect("retried event send"),
                Poll::Pending => panic!("dropped reserve waiter must release its queue position"),
            }
        };
        assert_eq!(
            retry,
            StreamingSseTransportStep::Sent {
                bytes: second_wire.len(),
                total_bytes: first_wire.len() + second_wire.len(),
            }
        );
        assert!(stream.pending_event_chunk.is_none());
        assert_eq!(stream.bytes_emitted(), first_wire.len() + second_wire.len());
        assert_eq!(
            sender.total_bytes(),
            (first_wire.len() + second_wire.len()) as u64
        );

        let second_frame = poll_body(&mut body)
            .expect("retried second frame")
            .expect("retried second frame ok");
        assert_eq!(
            second_frame.into_data().expect("data frame").chunk(),
            second_wire
        );
        let complete =
            block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("complete send");
        assert_eq!(complete, StreamingSseTransportStep::Complete);
    }

    #[test]
    fn streaming_sse_h1_dropped_pending_heartbeat_does_not_precommit() {
        let cx = Cx::for_testing();
        let heartbeat_wire = b":tick\n\n";
        let mut stream = StreamingSse::empty().heartbeat_comment("tick");
        let (response, mut sender) = stream.h1_chunked_response(&cx, 1);
        let mut body = response.body;

        block_on(stream.send_h1_heartbeat(&cx, &mut sender)).expect("first heartbeat send");
        assert_eq!(stream.bytes_emitted(), heartbeat_wire.len());
        assert_eq!(stream.event_bytes_emitted, 0);
        assert_eq!(sender.total_bytes(), heartbeat_wire.len() as u64);

        {
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut future = Box::pin(stream.send_h1_heartbeat(&cx, &mut sender));
            assert!(
                future.as_mut().poll(&mut task_cx).is_pending(),
                "a full H1 body channel must backpressure the second heartbeat"
            );
        }

        assert_eq!(stream.bytes_emitted(), heartbeat_wire.len());
        assert_eq!(stream.event_bytes_emitted, 0);
        assert_eq!(sender.total_bytes(), heartbeat_wire.len() as u64);
        let first_frame = poll_body(&mut body)
            .expect("first heartbeat frame")
            .expect("first heartbeat frame ok");
        assert_eq!(
            first_frame.into_data().expect("data frame").chunk(),
            heartbeat_wire
        );

        let retry = {
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut future = Box::pin(stream.send_h1_heartbeat(&cx, &mut sender));
            match future.as_mut().poll(&mut task_cx) {
                Poll::Ready(result) => result.expect("retried heartbeat send"),
                Poll::Pending => panic!("dropped reserve waiter must release its queue position"),
            }
        };
        assert_eq!(
            retry,
            StreamingSseTransportStep::Sent {
                bytes: heartbeat_wire.len(),
                total_bytes: heartbeat_wire.len() * 2,
            }
        );
        assert_eq!(stream.bytes_emitted(), heartbeat_wire.len() * 2);
        assert_eq!(stream.event_bytes_emitted, 0);
        assert_eq!(sender.total_bytes(), (heartbeat_wire.len() * 2) as u64);
        let second_frame = poll_body(&mut body)
            .expect("retried heartbeat frame")
            .expect("retried heartbeat frame ok");
        assert_eq!(
            second_frame.into_data().expect("data frame").chunk(),
            heartbeat_wire
        );
    }

    #[test]
    fn streaming_sse_h1_closed_body_does_not_commit_prepared_event() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![SseEvent::default().data("pending")]);
        let (response, mut sender) = stream.h1_chunked_response(&cx, 1);
        drop(response.body);

        let error = block_on(stream.send_next_h1_chunk(&cx, &mut sender))
            .expect_err("closed body must reject the prepared event");

        assert!(matches!(
            error,
            StreamingSseTransportError::Transport(HttpError::BodyChannelClosed)
        ));
        assert!(stream.is_closed());
        assert!(cx.is_cancel_requested());
        assert!(stream.pending_event_chunk.is_none());
        assert_eq!(stream.source.remaining(), 0);
        assert_eq!(stream.bytes_emitted(), 0);
        assert_eq!(stream.event_bytes_emitted, 0);
        assert_eq!(sender.total_bytes(), 0);
    }

    #[test]
    fn streaming_sse_h1_cancelled_pending_send_does_not_commit_event() {
        let cx = Cx::for_testing();
        let first_wire = b"data:first\n\n";
        let mut stream = StreamingSse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("pending"),
            SseEvent::default().data("never-polled"),
        ]);
        let (_response, mut sender) = stream.h1_chunked_response(&cx, 1);

        block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("first send");
        let error = {
            let waker = noop_waker();
            let mut task_cx = Context::from_waker(&waker);
            let mut future = Box::pin(stream.send_next_h1_chunk(&cx, &mut sender));
            assert!(future.as_mut().poll(&mut task_cx).is_pending());
            cx.set_cancel_requested(true);
            match future.as_mut().poll(&mut task_cx) {
                Poll::Ready(result) => result.expect_err("cancelled send must fail"),
                Poll::Pending => panic!("cancelled reserve must become ready"),
            }
        };

        assert!(matches!(
            error,
            StreamingSseTransportError::Transport(HttpError::BodyCancelled)
        ));
        assert!(stream.is_closed());
        assert!(stream.pending_event_chunk.is_none());
        assert_eq!(stream.source.remaining(), 0);
        assert_eq!(stream.bytes_emitted(), first_wire.len());
        assert_eq!(stream.event_bytes_emitted, first_wire.len());
        assert_eq!(sender.total_bytes(), first_wire.len() as u64);
    }

    #[test]
    fn streaming_sse_h1_transport_sends_heartbeat_comment() {
        let cx = Cx::for_testing();
        let mut stream =
            StreamingSse::new(vec![SseEvent::default().data("payload")]).heartbeat_comment("tick");
        let (response, mut sender) = stream.h1_chunked_response(&cx, 2);
        let mut body = response.body;

        let heartbeat =
            block_on(stream.send_h1_heartbeat(&cx, &mut sender)).expect("heartbeat send");
        assert_eq!(
            heartbeat,
            StreamingSseTransportStep::Sent {
                bytes: ":tick\n\n".len(),
                total_bytes: ":tick\n\n".len(),
            }
        );
        let heartbeat_frame = poll_body(&mut body)
            .expect("heartbeat frame")
            .expect("heartbeat frame ok");
        assert_eq!(
            heartbeat_frame.into_data().expect("data frame").chunk(),
            b":tick\n\n"
        );

        let event = block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("event send");
        assert_eq!(
            event,
            StreamingSseTransportStep::Sent {
                bytes: "data:payload\n\n".len(),
                total_bytes: ":tick\n\n".len() + "data:payload\n\n".len(),
            }
        );
        let event_frame = poll_body(&mut body)
            .expect("event frame")
            .expect("event frame ok");
        assert_eq!(
            event_frame.into_data().expect("data frame").chunk(),
            b"data:payload\n\n"
        );
    }

    #[test]
    fn streaming_sse_h1_transport_empty_stream_finishes_body() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::empty();
        let (response, mut sender) = stream.h1_chunked_response(&cx, 1);
        let mut body = response.body;

        let step = block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("finish");

        assert_eq!(step, StreamingSseTransportStep::Complete);
        assert!(sender.is_finished());
        assert!(stream.is_closed());
        assert!(poll_body(&mut body).is_none());
    }

    #[test]
    fn streaming_sse_h1_transport_propagates_producer_error_without_commit() {
        struct FailingSource;

        impl StreamingSseSource for FailingSource {
            fn next_event(&mut self, _cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError> {
                Err(StreamingSseError::Producer("synthetic failure".to_string()))
            }
        }

        let cx = Cx::for_testing();
        let mut stream = StreamingSse::from_source(FailingSource);
        let (_response, mut sender) = stream.h1_chunked_response(&cx, 1);

        let err = block_on(stream.send_next_h1_chunk(&cx, &mut sender))
            .expect_err("producer error should surface");

        assert!(matches!(
            err,
            StreamingSseTransportError::Stream(StreamingSseError::Producer(message))
                if message == "synthetic failure"
        ));
        assert_eq!(stream.bytes_emitted(), 0);
        assert_eq!(sender.total_bytes(), 0);
    }

    #[test]
    fn streaming_sse_h1_transport_rejects_event_and_total_overflow() {
        let cx = Cx::for_testing();

        let mut oversized =
            StreamingSse::new(vec![SseEvent::default().data("abcdef")]).max_event_bytes(8);
        let (_response, mut sender) = oversized.h1_chunked_response(&cx, 1);
        let err = block_on(oversized.send_next_h1_chunk(&cx, &mut sender))
            .expect_err("oversized event should fail");
        assert!(matches!(
            err,
            StreamingSseTransportError::Stream(StreamingSseError::EventTooLarge {
                actual,
                max: 8,
            }) if actual > 8
        ));
        assert_eq!(oversized.bytes_emitted(), 0);
        assert_eq!(sender.total_bytes(), 0);

        let first_len = "data:one\n\n".len();
        let mut over_total = StreamingSse::new(vec![
            SseEvent::default().data("one"),
            SseEvent::default().data("two"),
        ])
        .max_total_bytes(first_len);
        let (response, mut sender) = over_total.h1_chunked_response(&cx, 1);
        let mut body = response.body;
        block_on(over_total.send_next_h1_chunk(&cx, &mut sender)).expect("first send");
        let _ = poll_body(&mut body)
            .expect("first frame")
            .expect("ok frame");
        let err = block_on(over_total.send_next_h1_chunk(&cx, &mut sender))
            .expect_err("total overflow should fail");
        assert!(matches!(
            err,
            StreamingSseTransportError::Stream(StreamingSseError::TotalBytesExceeded {
                actual,
                max,
            }) if actual > max && max == first_len
        ));
        assert_eq!(over_total.bytes_emitted(), first_len);
        assert_eq!(sender.total_bytes(), first_len as u64);
    }

    #[test]
    fn streaming_sse_h1_transport_disconnect_before_first_chunk_finishes_empty() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![SseEvent::default().data("pending")]);
        let (response, mut sender) = stream.h1_chunked_response(&cx, 1);
        let mut body = response.body;

        stream.cancel_for_disconnect(&cx);
        let step =
            block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("closed stream finish");

        assert_eq!(step, StreamingSseTransportStep::Complete);
        assert!(cx.is_cancel_requested());
        assert_eq!(stream.bytes_emitted(), 0);
        assert!(body_has_no_more_data_after_cancel(poll_body(&mut body)));
    }

    #[test]
    fn streaming_sse_h1_transport_disconnect_after_committed_chunk_stops_later_events() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("second"),
        ]);
        let (response, mut sender) = stream.h1_chunked_response(&cx, 1);
        let mut body = response.body;

        block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("first send");
        let frame = poll_body(&mut body)
            .expect("first frame")
            .expect("first frame ok");
        assert_eq!(
            frame.into_data().expect("data frame").chunk(),
            b"data:first\n\n"
        );

        stream.cancel_for_disconnect(&cx);
        let step =
            block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("closed stream finish");

        assert_eq!(step, StreamingSseTransportStep::Complete);
        assert!(cx.is_cancel_requested());
        assert_eq!(stream.bytes_emitted(), "data:first\n\n".len());
        assert!(body_has_no_more_data_after_cancel(poll_body(&mut body)));
    }

    #[test]
    fn streaming_sse_h1_transport_cancellation_while_producing_closes_source() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let mut stream = StreamingSse::new(vec![SseEvent::default().data("pending")]);
        let (_response, mut sender) = stream.h1_chunked_response(&cx, 1);

        let err = block_on(stream.send_next_h1_chunk(&cx, &mut sender))
            .expect_err("cancelled stream should fail");

        assert!(matches!(
            err,
            StreamingSseTransportError::Stream(StreamingSseError::Cancelled)
        ));
        assert!(stream.is_closed());
        assert_eq!(stream.bytes_emitted(), 0);
    }

    // ================================================================
    // Data type coverage
    // ================================================================

    #[test]
    fn sse_event_debug_clone_default_eq() {
        let event = SseEvent::default();
        let dbg = format!("{event:?}");
        assert!(dbg.contains("SseEvent"));

        let cloned = event.clone();
        assert_eq!(event, cloned);

        let event2 = SseEvent::default().data("different");
        assert_ne!(event, event2);
    }

    #[test]
    fn sse_debug_clone() {
        let sse = Sse::event(SseEvent::default().data("test"));
        let dbg = format!("{sse:?}");
        assert!(dbg.contains("Sse"));
    }

    // ================================================================
    // Realistic usage patterns
    // ================================================================

    #[test]
    fn sse_json_events() {
        let sse = Sse::new(vec![
            SseEvent::default()
                .event("update")
                .data(r#"{"count": 1}"#)
                .id("1"),
            SseEvent::default()
                .event("update")
                .data(r#"{"count": 2}"#)
                .id("2"),
        ]);
        let body = sse.to_body();
        assert!(body.contains("event:update"));
        assert!(body.contains(r#"data:{"count": 1}"#));
        assert!(body.contains("id:1"));
        assert!(body.contains(r#"data:{"count": 2}"#));
        assert!(body.contains("id:2"));
    }

    #[test]
    fn sse_with_retry_and_reconnection() {
        let sse = Sse::new(vec![
            SseEvent::default().retry(5000).comment("reconnect hint"),
            SseEvent::default().event("heartbeat").data(""),
        ]);
        let body = sse.to_body();
        assert!(body.contains("retry:5000"));
        assert!(body.contains(":reconnect hint"));
        assert!(body.contains("event:heartbeat"));
    }

    // ─── br-asupersync-tamnew bounds ─────────────────────────────────

    #[test]
    fn sse_max_events_cap_returns_413() {
        // br-asupersync-tamnew: per-response event count cap rejects with
        // 413 Payload Too Large when exceeded.
        let events: Vec<SseEvent> = (0..6)
            .map(|i| SseEvent::default().data(format!("e{i}")))
            .collect();
        let sse = Sse::new(events).max_events(5);
        let resp = sse.into_response();
        assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(
            body.contains("max_events"),
            "body should mention the cap, got {body:?}"
        );
    }

    #[test]
    fn sse_max_events_cap_at_limit_serves_normally() {
        // Exactly at the cap = OK (off-by-one regression guard).
        let events: Vec<SseEvent> = (0..5)
            .map(|i| SseEvent::default().data(format!("e{i}")))
            .collect();
        let sse = Sse::new(events).max_events(5);
        let resp = sse.into_response();
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn sse_max_total_bytes_cap_returns_413() {
        // br-asupersync-tamnew: per-response body byte cap rejects with 413.
        // Each event body includes "data:e<i>\n\n" overhead too.
        let events = vec![SseEvent::default().data("a".repeat(1024))];
        let sse = Sse::new(events).max_total_bytes(100);
        let resp = sse.into_response();
        assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(
            body.contains("max_total_bytes"),
            "body should mention the cap, got {body:?}"
        );
    }

    #[test]
    fn sse_default_caps_allow_typical_response() {
        // Smoke: default caps (100k events / 16 MiB) easily allow normal use.
        let events: Vec<SseEvent> = (0..10)
            .map(|i| SseEvent::default().data(format!("event-{i}")))
            .collect();
        let resp = Sse::new(events).into_response();
        assert_eq!(resp.status, StatusCode::OK);
    }

    /// A source that overrides `poll_next_event` to stay idle forever.
    struct IdleForeverSource;
    impl StreamingSseSource for IdleForeverSource {
        fn next_event(&mut self, _cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError> {
            // Never reached via the poll path; a defensive completion if a
            // caller uses the blocking API directly.
            Ok(None)
        }
        fn poll_next_event(
            &mut self,
            _cx: &Cx,
            _task_cx: &mut Context<'_>,
        ) -> Poll<Result<Option<SseEvent>, StreamingSseError>> {
            Poll::Pending
        }
    }

    #[test]
    fn poll_next_event_default_delegates_and_override_can_idle() {
        // br-asupersync-sse7kp2: the default poll_next_event delegates to the
        // blocking next_event, so existing sources are always Ready (never idle)
        // — backwards-compatible; a source that overrides it can report Pending
        // to stay idle-but-open, which is the capability the fix adds.
        let cx = Cx::for_testing();
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        // Default (non-overriding) source: VecSseSource defines only next_event.
        let mut default_stream = StreamingSse::new(vec![SseEvent::default().data("x")]);
        assert!(
            matches!(
                default_stream.poll_prepare_next_event_chunk(&cx, &mut task_cx),
                Poll::Ready(Ok(true))
            ),
            "a default source must poll Ready with its event, exactly like the blocking path"
        );

        // Overriding source: idle → Pending (open), not Ok(None) (complete).
        let mut idle_stream = StreamingSse::from_source(IdleForeverSource);
        assert!(
            idle_stream
                .poll_prepare_next_event_chunk(&cx, &mut task_cx)
                .is_pending(),
            "an idle source's poll-prepare must be Pending (keep the stream open), not complete"
        );
        assert!(
            idle_stream.heartbeat_interval.is_none(),
            "heartbeat_interval defaults to None (blocking behavior preserved)"
        );
    }

    #[test]
    fn idle_source_emits_a_heartbeat_after_the_interval() {
        // br-asupersync-sse7kp2: a source that stays idle (poll_next_event
        // Pending) with a heartbeat_interval must emit a keep-alive comment
        // rather than block the task, so the stream stays open and a dead peer
        // is detected on the flush. Uses the native runtime so the timeout's
        // Sleep is driven by a real timer driver.
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        runtime.block_on(async {
            let cx = Cx::current().expect("runtime installs a Cx with a timer driver");
            let mut stream = StreamingSse::from_source(IdleForeverSource)
                .heartbeat_interval(Some(Duration::from_millis(20)));
            let (response, mut sender) = stream.h1_chunked_response(&cx, 2);
            let mut body = response.body;

            let step = stream
                .send_next_h1_chunk_with_heartbeat(&cx, &mut sender, Duration::from_millis(20))
                .await
                .expect("an idle source must emit a heartbeat, not block or error");
            assert!(
                matches!(step, StreamingSseTransportStep::Sent { .. }),
                "a heartbeat is a Sent step, got {step:?}"
            );

            let frame = poll_body(&mut body)
                .expect("a heartbeat frame must be committed")
                .expect("heartbeat frame ok");
            let bytes = frame.into_data().expect("data frame").chunk().to_vec();
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                text.contains("keep-alive"),
                "the heartbeat must be a keep-alive comment, got {text:?}"
            );
        });
    }

    /// A live source that idles until released, then yields one event. Its
    /// blocking `next_event` must never be called. The test re-polls by hand,
    /// so the source does not keep the waker.
    struct ReleasedLaterSource {
        released: std::sync::Arc<std::sync::atomic::AtomicBool>,
        sent: bool,
    }
    impl StreamingSseSource for ReleasedLaterSource {
        fn next_event(&mut self, _cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError> {
            panic!("the live step called the blocking next_event");
        }
        fn poll_next_event(
            &mut self,
            _cx: &Cx,
            _task_cx: &mut Context<'_>,
        ) -> Poll<Result<Option<SseEvent>, StreamingSseError>> {
            if self.sent {
                return Poll::Ready(Ok(None));
            }
            if !self.released.load(std::sync::atomic::Ordering::Acquire) {
                return Poll::Pending;
            }
            self.sent = true;
            Poll::Ready(Ok(Some(SseEvent::default().data("live"))))
        }
    }

    #[test]
    fn live_step_without_heartbeat_uses_poll_next_event() {
        // br-asupersync-a1q12q (round 9 M3): with no heartbeat interval, the
        // live step the HTTP/1 server runs called the blocking next_event, so a
        // live source either ended its stream at once or held a worker thread.
        let cx = Cx::for_testing();
        let released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut stream = StreamingSse::from_source(ReleasedLaterSource {
            released: std::sync::Arc::clone(&released),
            sent: false,
        });
        assert!(stream.heartbeat_interval.is_none());
        let (response, mut sender) = stream.h1_chunked_response(&cx, 2);
        let mut body = response.body;
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        {
            let mut step = std::pin::pin!(stream.send_next_h1_chunk_live(&cx, &mut sender));
            assert!(
                step.as_mut().poll(&mut task_cx).is_pending(),
                "an idle live source keeps the step pending"
            );
            released.store(true, std::sync::atomic::Ordering::Release);
            let sent = loop {
                match step.as_mut().poll(&mut task_cx) {
                    Poll::Ready(sent) => break sent,
                    Poll::Pending => std::thread::yield_now(),
                }
            };
            assert_eq!(
                sent.expect("event send"),
                StreamingSseTransportStep::Sent {
                    bytes: "data:live\n\n".len(),
                    total_bytes: "data:live\n\n".len(),
                }
            );
        }
        let frame = poll_body(&mut body)
            .expect("event frame")
            .expect("event frame ok");
        assert_eq!(
            frame.into_data().expect("data frame").chunk(),
            b"data:live\n\n"
        );
        let complete = block_on(stream.send_next_h1_chunk_live(&cx, &mut sender)).expect("finish");
        assert_eq!(complete, StreamingSseTransportStep::Complete);
    }
