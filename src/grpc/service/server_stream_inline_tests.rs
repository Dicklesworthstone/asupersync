    use super::*;
    use crate::cx::Cx;
    use crate::grpc::service::{ServiceDescriptor, ServiceHandler};
    use crate::grpc::status::Code;
    use crate::grpc::streaming::{MetadataValue, Request};
    use std::cell::Cell;
    use std::marker::PhantomPinned;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    struct PinnedSource {
        position: Cell<usize>,
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        _pin: PhantomPinned,
    }

    impl Streaming for PinnedSource {
        type Message = Bytes;

        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Bytes, Status>>> {
            let this = self.as_ref().get_ref();
            this.polls.fetch_add(1, Ordering::SeqCst);
            let position = this.position.replace(this.position.get() + 1);
            Poll::Ready((position == 0).then(|| Ok(Bytes::from_static(b"private payload"))))
        }
    }

    impl Drop for PinnedSource {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn source(polls: &Arc<AtomicUsize>, drops: &Arc<AtomicUsize>) -> PinnedSource {
        PinnedSource {
            position: Cell::new(0),
            polls: Arc::clone(polls),
            drops: Arc::clone(drops),
            _pin: PhantomPinned,
        }
    }

    #[test]
    fn registered_stream_is_lazy_pinned_and_releases_its_source_once() {
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut trailers = Metadata::new();
        assert!(trailers.insert("x-receipt", "private receipt"));
        let response = RegisteredServerStream::new(source(&polls, &drops)).with_trailers(trailers);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let debug = format!("{response:?}");
        assert!(!debug.contains("private"));
        let (mut stream, trailers) = response.into_parts();
        assert!(matches!(
            trailers.get("x-receipt"),
            Some(MetadataValue::Ascii(value)) if value == "private receipt"
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            stream.as_mut().poll_next(&mut cx),
            Poll::Ready(Some(Ok(value))) if value.as_ref() == b"private payload"
        ));
        assert!(matches!(stream.as_mut().poll_next(&mut cx), Poll::Ready(None)));
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        drop(stream);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unpolled_registered_stream_drop_releases_without_calling_user_poll() {
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        drop(RegisteredServerStream::new(source(&polls, &drops)));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn initial_metadata_stays_separate_from_trailers_and_the_source_stays_lazy() {
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut initial = Metadata::new();
        assert!(initial.insert("x-start", "private initial"));
        assert!(initial.insert_bin("x-token-bin", Bytes::from_static(b"\x00\xff")));
        let mut trailers = Metadata::new();
        assert!(trailers.insert("x-end", "private terminal"));
        let response = RegisteredServerStream::new(source(&polls, &drops))
            .with_initial_metadata(initial)
            .with_trailers(trailers);
        assert_eq!(response.initial_metadata().len(), 2);
        assert!(!format!("{response:?}").contains("private"));
        let (stream, initial, trailers) = response.into_parts_with_metadata();
        assert!(matches!(
            initial.get("x-start"),
            Some(MetadataValue::Ascii(value)) if value == "private initial"
        ));
        assert!(matches!(
            initial.get("x-token-bin"),
            Some(MetadataValue::Binary(value)) if value.as_ref() == b"\x00\xff"
        ));
        assert!(initial.get("x-end").is_none());
        assert!(trailers.get("x-start").is_none());
        assert!(matches!(
            trailers.get("x-end"),
            Some(MetadataValue::Ascii(value)) if value == "private terminal"
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        drop(stream);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        // Existing callers keep the original two-part signature and receive
        // their successful-completion trailers, never the initial block.
        let mut initial = Metadata::new();
        assert!(initial.insert("x-start", "not a trailer"));
        let response = RegisteredServerStream::new(source(&polls, &drops))
            .with_initial_metadata(initial);
        let (stream, trailers) = response.into_parts();
        assert!(trailers.is_empty());
        drop(stream);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn legacy_service_remains_object_safe_and_refuses_unimplemented_streams() {
        struct Legacy;
        static DESCRIPTOR: ServiceDescriptor = ServiceDescriptor::new("Legacy", "test", &[]);
        impl ServiceHandler for Legacy {
            fn descriptor(&self) -> &ServiceDescriptor {
                &DESCRIPTOR
            }

            fn method_names(&self) -> Vec<&str> {
                Vec::new()
            }
        }
        fn require_send<T: Send>(_: &T) {}
        let service: Box<dyn ServiceHandler> = Box::new(Legacy);
        assert!(!service.defer_response_headers("/test.Legacy/Watch"));
        let cx = Cx::for_testing();
        let mut future = service.call_server_streaming(
            &cx,
            "/test.Legacy/Watch",
            Request::new(Bytes::new()),
            Metadata::new(),
        );
        require_send(&future);
        let mut task_cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            future.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(status)) if status.code() == Code::Unimplemented
        ));
    }
