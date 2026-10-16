    use super::*;
    use crate::net::atp::protocol::{
        CapabilityAction, CapabilityGrant, CapabilityGrantId, CapabilityScope, PeerId,
        SessionContextKind,
    };
    use crate::net::atp::sdk::{AtpSdk, SessionConfig, SessionOptions, TransferPhase};
    use futures_lite::future::block_on;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    struct CountWaker(Arc<AtomicUsize>);

    impl Wake for CountWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker(counter: Arc<AtomicUsize>) -> Waker {
        Waker::from(Arc::new(CountWaker(counter)))
    }

    fn progress(id: &str, bytes_transferred: u64) -> TransferProgress {
        TransferProgress {
            transfer_id: TransferId::new(id),
            bytes_transferred,
            total_bytes: 100,
            speed_bytes_per_sec: 10,
            eta_ms: Some(1_000),
            phase: TransferPhase::DataTransfer,
            active_paths: 1,
            repair_symbols_active: false,
        }
    }

    fn writer_with_progress_receiver(
        progress_cx: Cx,
        progress_rx: mpsc::Receiver<TransferProgress>,
    ) -> AtpWriter {
        let (data_tx, _data_rx) = mpsc::channel(1);
        let (cancel_tx, _cancel_rx) = mpsc::channel(1);
        AtpWriter {
            transfer_id: TransferId::new("owned-writer-progress"),
            data_tx,
            progress_rx,
            progress_cx,
            cancel_tx: Some(cancel_tx),
            obligation: None,
            config: StreamConfig::default(),
            state: WriterState::Ready,
        }
    }

    fn reader_with_progress_receiver(
        progress_cx: Cx,
        progress_rx: mpsc::Receiver<TransferProgress>,
    ) -> AtpReader {
        let (_data_tx, data_rx) = mpsc::channel(1);
        let (cancel_tx, _cancel_rx) = mpsc::channel(1);
        AtpReader {
            transfer_id: TransferId::new("owned-reader-progress"),
            data_rx,
            progress_rx,
            progress_cx,
            cancel_tx: Some(cancel_tx),
            obligation: None,
            config: StreamConfig::default(),
            state: ReaderState::Ready,
        }
    }

    #[test]
    fn sdk_progress_types_implement_owned_stream() {
        fn assert_owned_progress_stream<S>()
        where
            S: crate::stream::Stream<Item = TransferProgress>,
        {
        }

        assert_owned_progress_stream::<AtpWriter>();
        assert_owned_progress_stream::<AtpReader>();
    }

    #[test]
    fn owned_writer_progress_registers_sender_wake_without_self_wake() {
        let progress_cx = Cx::for_testing();
        let (progress_tx, progress_rx) = mpsc::channel(1);
        let mut writer = writer_with_progress_receiver(progress_cx, progress_rx);
        let stale_wake_count = Arc::new(AtomicUsize::new(0));
        let stale_waker = counting_waker(Arc::clone(&stale_wake_count));
        let mut stale_task_cx = Context::from_waker(&stale_waker);

        let pending = crate::stream::Stream::poll_next(Pin::new(&mut writer), &mut stale_task_cx);
        assert!(pending.is_pending());
        assert_eq!(stale_wake_count.load(Ordering::SeqCst), 0);

        let latest_wake_count = Arc::new(AtomicUsize::new(0));
        let latest_waker = counting_waker(Arc::clone(&latest_wake_count));
        let mut latest_task_cx = Context::from_waker(&latest_waker);
        assert!(
            crate::stream::Stream::poll_next(Pin::new(&mut writer), &mut latest_task_cx)
                .is_pending()
        );
        assert_eq!(stale_wake_count.load(Ordering::SeqCst), 0);
        assert_eq!(latest_wake_count.load(Ordering::SeqCst), 0);

        let expected = progress("writer", 25);
        progress_tx
            .try_send(expected.clone())
            .expect("progress send must fit");
        assert_eq!(stale_wake_count.load(Ordering::SeqCst), 0);
        assert_eq!(latest_wake_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            crate::stream::Stream::poll_next(Pin::new(&mut writer), &mut latest_task_cx),
            Poll::Ready(Some(expected))
        );

        drop(progress_tx);
        assert_eq!(
            crate::stream::Stream::poll_next(Pin::new(&mut writer), &mut latest_task_cx),
            Poll::Ready(None)
        );
    }

    #[test]
    fn owned_reader_progress_observes_creation_context_cancellation() {
        let progress_cx = Cx::for_testing();
        let (progress_tx, progress_rx) = mpsc::channel(1);
        let mut reader = reader_with_progress_receiver(progress_cx.clone(), progress_rx);
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(Arc::clone(&wake_count));
        let mut task_cx = Context::from_waker(&waker);

        assert!(crate::stream::Stream::poll_next(Pin::new(&mut reader), &mut task_cx).is_pending());
        assert_eq!(wake_count.load(Ordering::SeqCst), 0);
        progress_cx.set_cancel_requested(true);
        assert_eq!(
            crate::stream::Stream::poll_next(Pin::new(&mut reader), &mut task_cx),
            Poll::Ready(None)
        );
        progress_tx
            .try_send(progress("reader", 50))
            .expect("cancelled progress receiver remains connected");
        assert_eq!(wake_count.load(Ordering::SeqCst), 0);
    }

    fn granted_direct_options(config: &SessionConfig, peer: PeerId, label: &str) -> SessionOptions {
        SessionOptions::direct(peer).with_grants(vec![CapabilityGrant::new(
            CapabilityGrantId::from_label(label),
            peer,
            config.local_peer,
            [CapabilityAction::Read, CapabilityAction::Write],
            CapabilityScope::for_context(SessionContextKind::Direct),
        )])
    }

    fn assert_missing_stream_transport<T: std::fmt::Debug>(outcome: AtpOutcome<T>) {
        match outcome {
            AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented)) => {}
            other => panic!("stream setup must fail closed without transport: {other:?}"), // ubs:ignore
        }
    }

    #[test]
    fn stream_chunk_creation() {
        let data = b"test data".to_vec();
        let chunk = StreamChunk::new(data.clone(), 42, false);

        assert_eq!(chunk.data, data);
        assert_eq!(chunk.sequence, 42);
        assert!(!chunk.is_final);
        assert!(chunk.verify());

        // Test corrupted chunk
        let mut bad_chunk = chunk.clone();
        bad_chunk.data[0] = 0xFF; // Corrupt data
        assert!(!bad_chunk.verify());
    }

    #[test]
    fn atp_writer_creation() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options =
                granted_direct_options(&SessionConfig::default(), peer, "writer-open");
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let stream_config = StreamConfig::default();
            assert_missing_stream_transport(session.create_writer(&cx, stream_config).await);
        });

        crate::test_complete!("atp_writer_creation");
    }

    #[test]
    fn atp_reader_creation() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options =
                granted_direct_options(&SessionConfig::default(), peer, "reader-open");
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let stream_config = StreamConfig::default();
            assert_missing_stream_transport(session.create_reader(&cx, stream_config).await);
        });

        crate::test_complete!("atp_reader_creation");
    }

    #[test]
    fn writer_chunk_operations() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options =
                granted_direct_options(&SessionConfig::default(), peer, "writer-chunk");
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let stream_config = StreamConfig::default();
            assert_missing_stream_transport(session.create_writer(&cx, stream_config).await);
        });

        crate::test_complete!("writer_chunk_operations");
    }

    #[test]
    fn reader_chunk_operations() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options =
                granted_direct_options(&SessionConfig::default(), peer, "reader-chunk");
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let stream_config = StreamConfig::default();
            assert_missing_stream_transport(session.create_reader(&cx, stream_config).await);
        });

        crate::test_complete!("reader_chunk_operations");
    }

    #[test]
    fn async_write_interface() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options =
                granted_direct_options(&SessionConfig::default(), peer, "async-write");
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let stream_config = StreamConfig::default();
            assert_missing_stream_transport(session.create_writer(&cx, stream_config).await);
        });

        crate::test_complete!("async_write_interface");
    }

    #[test]
    fn async_read_interface() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config);

            let peer = PeerId::from_label("test_peer");
            let session_options =
                granted_direct_options(&SessionConfig::default(), peer, "async-read");
            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let stream_config = StreamConfig::default();
            assert_missing_stream_transport(session.create_reader(&cx, stream_config).await);
        });

        crate::test_complete!("async_read_interface");
    }
