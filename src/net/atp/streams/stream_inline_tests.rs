    use super::*;
    use crate::cx::{Cx, cap};

    fn test_cx() -> Cx<cap::All> {
        Cx::for_testing()
    }

    fn assert_receive_ok(outcome: Outcome<Vec<Bytes>, StreamError>, context: &str) -> Vec<Bytes> {
        match outcome {
            Outcome::Ok(received) => received,
            other => panic!("{context}: expected receive_data to succeed, got {other:?}"),
        }
    }

    #[test]
    fn test_stream_send_receive() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(0), true, StreamPriority::Data, true);

        // Queue some data for sending
        let data = Bytes::from("hello world");
        assert!(stream.queue_send(&cx, data.clone(), false).is_ok());
        assert!(stream.has_send_data());

        // Get data to send
        if let Some((offset, send_data, fin)) = stream.get_send_data(1000) {
            assert_eq!(offset, 0);
            assert_eq!(send_data, data);
            assert!(!fin);
        } else {
            panic!("Should have data to send");
        }

        // Receive the same data
        let received =
            assert_receive_ok(stream.receive_data(&cx, 0, data, false), "in-order receive");
        assert_eq!(received.len(), 1);
        assert_eq!(received[0], Bytes::from("hello world"));
    }

    #[test]
    fn test_stream_reset() {
        let mut stream = AtpStream::new(StreamId::new(4), true, StreamPriority::Control, false);

        assert!(!stream.is_closed());

        stream.reset(StreamResetCode::ApplicationClose);
        assert!(stream.is_closed());
        assert!(matches!(stream.state, StreamState::ResetLocal { .. }));
    }

    #[test]
    fn test_stream_out_of_order_receive() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(8), true, StreamPriority::Data, false);

        // Receive data out of order
        let data1 = assert_receive_ok(
            stream.receive_data(&cx, 5, Bytes::from("world"), false),
            "out-of-order suffix receive",
        );
        assert_eq!(data1.len(), 0); // Buffered, not delivered

        let data2 = assert_receive_ok(
            stream.receive_data(&cx, 0, Bytes::from("hello"), false),
            "out-of-order prefix receive",
        );
        assert_eq!(data2.len(), 2); // Both segments delivered
        assert_eq!(data2[0], Bytes::from("hello"));
        assert_eq!(data2[1], Bytes::from("world"));
    }

    #[test]
    fn test_stream_fin_handling() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(12), true, StreamPriority::Data, true);

        // Send with FIN
        let data = Bytes::from("final data");
        assert!(stream.queue_send(&cx, data.clone(), true).is_ok());

        // Get data should include FIN
        if let Some((offset, send_data, fin)) = stream.get_send_data(1000) {
            assert_eq!(offset, 0);
            assert_eq!(send_data, data);
            assert!(fin);
        }

        // Receive with FIN should complete the stream
        let received = assert_receive_ok(
            stream.receive_data(&cx, 0, data, true),
            "receive with final size",
        );
        assert_eq!(received.len(), 1);
        assert!(matches!(stream.receive_state, ReceiveState::DataRecvd));
    }

    #[test]
    fn out_of_order_fin_completes_when_gap_is_filled() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(16), true, StreamPriority::Data, false);

        let suffix = assert_receive_ok(
            stream.receive_data(&cx, 5, Bytes::from("world"), true),
            "out-of-order final suffix receive",
        );
        assert!(suffix.is_empty());
        assert!(matches!(stream.receive_state, ReceiveState::SizeKnown));
        assert!(matches!(stream.state, StreamState::Open));

        let delivered = assert_receive_ok(
            stream.receive_data(&cx, 0, Bytes::from("hello"), false),
            "prefix receive fills final gap",
        );

        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0], Bytes::from("hello"));
        assert_eq!(delivered[1], Bytes::from("world"));
        assert!(matches!(stream.receive_state, ReceiveState::DataRecvd));
        assert!(matches!(stream.state, StreamState::RemoteClosed));
    }

    #[test]
    fn test_stream_close_emits_fin_only_frame() {
        let mut stream = AtpStream::new(StreamId::new(16), true, StreamPriority::Data, true);

        stream.close();

        if let Some((offset, data, fin)) = stream.get_send_data(1000) {
            assert_eq!(offset, 0);
            assert!(data.is_empty());
            assert!(fin);
        } else {
            panic!("close without buffered data should emit a FIN-only frame");
        }

        assert!(!stream.has_send_data());
        assert!(matches!(stream.state, StreamState::LocalClosed));
    }

    #[test]
    fn test_stream_close_fin_covers_buffered_unsent_data() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(20), true, StreamPriority::Data, true);

        assert!(stream.queue_send(&cx, Bytes::from("hello"), false).is_ok());
        assert!(stream.queue_send(&cx, Bytes::from("world"), false).is_ok());

        stream.close();

        if let Some((offset, data, fin)) = stream.get_send_data(5) {
            assert_eq!(offset, 0);
            assert_eq!(data, Bytes::from("hello"));
            assert!(!fin);
        } else {
            panic!("first buffered segment should be sendable after close");
        }

        if let Some((offset, data, fin)) = stream.get_send_data(5) {
            assert_eq!(offset, 5);
            assert_eq!(data, Bytes::from("world"));
            assert!(fin);
        } else {
            panic!("final buffered segment should carry FIN after close");
        }

        assert!(!stream.has_send_data());
        assert!(matches!(stream.state, StreamState::LocalClosed));
    }

    #[test]
    fn test_stream_queue_fin_accounts_for_prior_buffered_data() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(24), true, StreamPriority::Data, true);

        assert!(stream.queue_send(&cx, Bytes::from("hello"), false).is_ok());
        assert!(stream.queue_send(&cx, Bytes::from("world"), true).is_ok());

        if let Some((offset, data, fin)) = stream.get_send_data(5) {
            assert_eq!(offset, 0);
            assert_eq!(data, Bytes::from("hello"));
            assert!(!fin);
        } else {
            panic!("previously queued data should be sent before FIN");
        }

        if let Some((offset, data, fin)) = stream.get_send_data(5) {
            assert_eq!(offset, 5);
            assert_eq!(data, Bytes::from("world"));
            assert!(fin);
        } else {
            panic!("segment queued with FIN should carry FIN at combined final size");
        }

        assert!(!stream.has_send_data());
        assert!(matches!(stream.state, StreamState::LocalClosed));
    }

    #[test]
    fn test_stream_get_send_data_zero_budget_does_not_emit_payload_frame() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(28), true, StreamPriority::Data, true);

        assert!(stream.queue_send(&cx, Bytes::from("hello"), false).is_ok());

        assert!(stream.get_send_data(0).is_none());
        assert!(stream.has_send_data());

        if let Some((offset, data, fin)) = stream.get_send_data(5) {
            assert_eq!(offset, 0);
            assert_eq!(data, Bytes::from("hello"));
            assert!(!fin);
        } else {
            panic!("payload should still be sendable after zero-budget poll");
        }
    }

    #[test]
    fn test_stream_rejects_queue_send_after_final_size_is_known() {
        let cx = test_cx();
        let mut stream = AtpStream::new(StreamId::new(32), true, StreamPriority::Data, true);

        assert!(stream.queue_send(&cx, Bytes::from("final"), true).is_ok());

        match stream.queue_send(&cx, Bytes::from("late"), false) {
            Outcome::Err(StreamError::InvalidState { stream_id, state }) => {
                assert_eq!(stream_id, StreamId::new(32));
                assert!(state.contains("final size"));
            }
            other => panic!("late send after FIN should be rejected, got {other:?}"),
        }
    }
