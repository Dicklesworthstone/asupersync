    use super::*;

    #[test]
    fn test_stream_creation() {
        let stream = AtpH3Stream::new(42, StreamDirection::Bidirectional);

        assert_eq!(stream.stream_id(), 42);
        assert_eq!(stream.direction(), &StreamDirection::Bidirectional);
        assert_eq!(stream.state(), &StreamState::Open);
        assert!(stream.can_send());
        assert!(stream.can_receive());
        assert!(!stream.is_closed());
    }

    #[test]
    fn test_stream_direction_capabilities() {
        let mut bi_stream = AtpH3Stream::new(0, StreamDirection::Bidirectional);
        let mut out_stream = AtpH3Stream::new(4, StreamDirection::Outbound);
        let mut in_stream = AtpH3Stream::new(8, StreamDirection::Inbound);

        // Bidirectional can send and receive
        assert!(bi_stream.can_send());
        assert!(bi_stream.can_receive());

        // Outbound can only send
        assert!(out_stream.can_send());
        assert!(!out_stream.can_receive());

        // Inbound can only receive
        assert!(!in_stream.can_send());
        assert!(in_stream.can_receive());

        // Test actual operations
        assert!(bi_stream.send(b"test").is_ok());
        assert!(bi_stream.receive(b"response").is_ok());

        assert!(out_stream.send(b"test").is_ok());
        assert!(out_stream.receive(b"response").is_err());

        assert!(in_stream.send(b"test").is_err());
        assert!(in_stream.receive(b"response").is_ok());
    }

    #[test]
    fn test_stream_send_receive() {
        let mut stream = AtpH3Stream::new(0, StreamDirection::Bidirectional);

        // Send data
        assert!(stream.send(b"hello").is_ok());
        assert!(stream.has_pending_send());
        assert_eq!(stream.send_queue_len(), 1);
        assert_eq!(stream.stats().bytes_sent, 0);

        // Get data to send
        let data = stream.next_send_data().unwrap();
        assert_eq!(data, b"hello");
        assert!(!stream.has_pending_send());
        assert_eq!(stream.stats().bytes_sent, 5);

        // Receive data
        assert!(stream.receive(b"world").is_ok());
        assert_eq!(stream.available(), 5);

        // Read received data
        let mut buf = [0u8; 10];
        let read = stream.read(&mut buf);
        assert_eq!(read, 5);
        assert_eq!(&buf[..read], b"world");
        assert_eq!(stream.available(), 0);
    }

    #[test]
    fn test_stream_buffer_limits() {
        let mut stream = AtpH3Stream::new(0, StreamDirection::Bidirectional);
        stream.set_max_buffer_size(100);
        stream.set_send_queue_high_water(2);

        // Fill send queue
        assert!(stream.send(b"data1").is_ok());
        assert!(stream.send(b"data2").is_ok());
        assert!(stream.send(b"data3").is_err()); // Queue full

        // Fill receive buffer
        let large_data = vec![0u8; 150];
        assert!(stream.receive(&large_data).is_err()); // Buffer too small
    }

    #[test]
    fn test_stream_close_lifecycle() {
        let mut stream = AtpH3Stream::new(0, StreamDirection::Bidirectional);

        // Close sending side
        assert!(stream.close_send().is_ok());
        assert_eq!(stream.state(), &StreamState::HalfClosedLocal);
        assert!(!stream.can_send());
        assert!(stream.can_receive());

        // Remote closes their side
        assert!(stream.handle_remote_close().is_ok());
        assert_eq!(stream.state(), &StreamState::Closed);
        assert!(!stream.can_send());
        assert!(!stream.can_receive());
        assert!(stream.is_closed());
    }

    #[test]
    fn test_stream_reset() {
        let mut stream = AtpH3Stream::new(0, StreamDirection::Bidirectional);

        // Add some data
        assert!(stream.send(b"test").is_ok());
        assert!(stream.receive(b"data").is_ok());

        // Reset stream
        assert!(stream.reset("Test reset".to_string()).is_ok());
        assert!(matches!(stream.state(), StreamState::Error(_)));
        assert!(stream.is_closed());
        assert_eq!(stream.send_queue_len(), 0);
        assert_eq!(stream.available(), 0);

        // Cannot send/receive after reset
        assert!(stream.send(b"more").is_err());
        assert!(stream.receive(b"more").is_err());
    }

    #[test]
    fn test_peer_reset() {
        let mut stream = AtpH3Stream::new(0, StreamDirection::Bidirectional);

        assert!(stream.send(b"test").is_ok());
        assert!(stream.receive(b"data").is_ok());

        stream.handle_peer_reset();
        assert_eq!(stream.state(), &StreamState::Reset);
        assert!(stream.is_closed());
        assert_eq!(stream.send_queue_len(), 0);
        assert_eq!(stream.available(), 0);
    }

    #[test]
    fn test_stream_stats() {
        let mut stream = AtpH3Stream::new(42, StreamDirection::Bidirectional);

        assert!(stream.send(b"hello").is_ok());
        assert!(stream.receive(b"world").is_ok());

        let stats = stream.stats();
        assert_eq!(stats.stream_id, 42);
        assert_eq!(stats.direction, StreamDirection::Bidirectional);
        assert_eq!(stats.state, StreamState::Open);
        assert_eq!(stats.bytes_received, 5);
        assert_eq!(stats.send_queue_len, 1);
        assert_eq!(stats.recv_buffer_len, 5);
        assert!(stats.uptime_ms > 0);
    }

    #[test]
    fn test_inbound_stream_close_restrictions() {
        let mut stream = AtpH3Stream::new(0, StreamDirection::Inbound);

        // Cannot close send on inbound-only stream
        assert!(stream.close_send().is_err());

        // But can handle remote close
        assert!(stream.handle_remote_close().is_ok());
        assert_eq!(stream.state(), &StreamState::HalfClosedRemote);
    }
