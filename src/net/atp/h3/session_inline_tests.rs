    use super::*;

    fn test_config() -> AdapterConfig {
        AdapterConfig {
            max_streams: 10,
            max_datagram_size: 1350,
            enable_unreliable_repair: true,
            connection_timeout_ms: 30000,
        }
    }

    #[test]
    fn test_session_creation() {
        let config = test_config();
        let session = H3Session::new("test-session".to_string(), &config).unwrap();

        assert_eq!(session.session_id(), "test-session");
        assert_eq!(session.state(), &SessionState::Connecting);
        assert!(!session.is_active());
        assert!(!session.is_closed());
        assert_eq!(session.stream_count(), 0);
    }

    #[test]
    fn test_session_activation() {
        let config = test_config();
        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();

        assert!(session.activate().is_ok());
        assert_eq!(session.state(), &SessionState::Active);
        assert!(session.is_active());

        // Cannot activate again
        assert!(session.activate().is_err());
    }

    #[test]
    fn test_stream_management() {
        let config = test_config();
        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();
        session.activate().unwrap();

        // Create streams
        let stream_id1 = session
            .create_stream(StreamDirection::Bidirectional)
            .unwrap();
        assert_eq!(stream_id1, 0);

        let stream_id2 = session.create_stream(StreamDirection::Outbound).unwrap();
        assert_eq!(stream_id2, 4);

        assert_eq!(session.stream_count(), 2);

        // Get stream
        assert!(session.get_stream(stream_id1).is_some());
        assert!(session.get_stream(999).is_none());

        // Close stream
        assert!(session.close_stream(stream_id1).is_ok());
        assert_eq!(session.stream_count(), 1);
        assert!(session.get_stream(stream_id1).is_none());
    }

    #[test]
    fn test_stream_limits() {
        let mut config = test_config();
        config.max_streams = 2;

        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();
        session.activate().unwrap();

        // Create maximum streams
        assert!(
            session
                .create_stream(StreamDirection::Bidirectional)
                .is_ok()
        );
        assert!(
            session
                .create_stream(StreamDirection::Bidirectional)
                .is_ok()
        );

        // Exceed limit
        assert!(
            session
                .create_stream(StreamDirection::Bidirectional)
                .is_err()
        );
    }

    #[test]
    fn test_stream_id_overflow_is_rejected() {
        let config = test_config();
        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();
        session.activate().unwrap();
        session.next_stream_id = u64::MAX - 3;

        let err = session
            .create_stream(StreamDirection::Bidirectional)
            .expect_err("overflowing stream id should fail");

        assert!(err.to_string().contains("Stream ID space exhausted"));
        assert_eq!(session.stream_count(), 0);
    }

    #[test]
    fn test_session_closure() {
        let config = test_config();
        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();
        session.activate().unwrap();

        // Create stream
        let _stream_id = session
            .create_stream(StreamDirection::Bidirectional)
            .unwrap();

        // Start close
        assert!(session.start_close().is_ok());
        assert_eq!(session.state(), &SessionState::Draining);

        // Complete close
        assert!(session.close().is_ok());
    }

    #[test]
    fn test_datagram_send() {
        let config = test_config();
        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();
        session.activate().unwrap();

        // Queue normal datagram
        let data = vec![0u8; 100];
        assert!(session.send_datagram(&data).is_ok());
        assert!(session.has_pending_datagram());
        assert_eq!(session.datagram_queue_len(), 1);
        assert_eq!(session.next_datagram(), Some(data));
        assert!(!session.has_pending_datagram());

        // Exceed size limit
        let large_data = vec![0u8; 2000];
        assert!(session.send_datagram(&large_data).is_err());
    }

    #[test]
    fn test_datagram_send_applies_backpressure() {
        let config = test_config();
        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();
        session.activate().unwrap();

        for _ in 0..64 {
            session.send_datagram(&[1, 2, 3]).unwrap();
        }

        let err = session
            .send_datagram(&[1, 2, 3])
            .expect_err("queue high water should apply backpressure");
        assert!(err.to_string().contains("Datagram send queue full"));
    }

    #[test]
    fn test_session_stats() {
        let config = test_config();
        let mut session = H3Session::new("test-session".to_string(), &config).unwrap();
        session.activate().unwrap();

        let _stream_id = session
            .create_stream(StreamDirection::Bidirectional)
            .unwrap();

        let stats = session.stats();
        assert_eq!(stats.session_id, "test-session");
        assert_eq!(stats.state, SessionState::Active);
        assert_eq!(stats.stream_count, 1);
        assert_eq!(stats.datagram_queue_len, 0);
        assert_eq!(stats.max_streams, 10);
        assert!(stats.uptime_ms > 0);
    }

    #[test]
    fn test_timeout_detection() {
        let mut config = test_config();
        config.connection_timeout_ms = 1; // Very short timeout

        let session = H3Session::new("test-session".to_string(), &config).unwrap();

        // Sleep briefly to trigger timeout
        std::thread::sleep(Duration::from_millis(10));
        assert!(session.is_timed_out());
    }
