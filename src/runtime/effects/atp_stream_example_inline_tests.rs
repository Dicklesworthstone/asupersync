    use super::*;
    use futures_lite::future;

    #[test]
    fn test_two_phase_send_success() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);

            // Reserve
            let permit = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle
            assert_eq!(stream.reserved_sends(), 1);
            assert_eq!(stream.send_queue_len(), 0);

            permit.commit(b"test data").unwrap(); // ubs:ignore - test oracle
            assert_eq!(stream.reserved_sends(), 0);
            assert_eq!(stream.send_queue_len(), 1);

            // Verify data can be retrieved
            let data = stream.next_send_data().unwrap(); // ubs:ignore - test oracle
            assert_eq!(data, b"test data");
        });
    }

    #[test]
    fn test_two_phase_send_abort() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);

            // Reserve
            let permit = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle
            assert_eq!(stream.reserved_sends(), 1);

            permit.abort();
            assert_eq!(stream.reserved_sends(), 0);
            assert_eq!(stream.send_queue_len(), 0);
        });
    }

    #[test]
    fn test_dropped_permit_releases_reservation() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);

            let permit = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle
            assert_eq!(stream.reserved_sends(), 1);

            drop(permit);
            assert_eq!(stream.reserved_sends(), 0);
            assert_eq!(stream.send_queue_len(), 0);
        });
    }

    #[test]
    fn test_queue_full_prevents_reservation() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);
            stream.send.lock().send_queue_high_water = 2;

            // Fill queue to high water mark
            let permit1 = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle
            let permit2 = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle

            // Third reservation should fail
            assert!(matches!(
                stream.reserve_send().await,
                Err(AtpStreamError::QueueFull)
            ));

            // Clean up by aborting reservations
            permit1.abort();
            permit2.abort();
        });
    }

    #[test]
    fn test_data_too_large() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);
            stream.send.lock().max_buffer_size = 10;

            let permit = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle

            let result = permit.commit(b"this is too long");
            assert!(matches!(result, Err(AtpStreamError::DataTooLarge { .. })));
            assert_eq!(stream.reserved_sends(), 0); // Reservation cleaned up
        });
    }

    #[test]
    fn test_reservations_are_independent() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);

            let first = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle
            let second = stream.reserve_send().await.unwrap(); // ubs:ignore - test oracle
            assert_eq!(stream.reserved_sends(), 2);

            first.abort();
            assert_eq!(stream.reserved_sends(), 1);

            second.commit(b"still reserved").unwrap(); // ubs:ignore - test oracle
            assert_eq!(stream.reserved_sends(), 0);
            assert_eq!(stream.next_send_data().unwrap(), b"still reserved");
        });
    }

    #[test]
    fn test_receive_rejects_over_limit_without_mutating_buffer() {
        let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Bidirectional);
        stream.send.lock().max_buffer_size = 5;

        stream.receive(b"abc").unwrap(); // ubs:ignore - test oracle

        let result = stream.receive(b"def");
        assert!(matches!(
            result,
            Err(AtpStreamError::DataTooLarge { size: 6, max: 5 })
        ));
        assert_eq!(stream.stats().recv_buffer_len, 3);

        let mut buffer = [0; 5];
        assert_eq!(stream.read_data(&mut buffer), 3);
        assert_eq!(&buffer[..3], b"abc");
    }

    #[test]
    fn test_cannot_send_on_inbound_stream() {
        future::block_on(async {
            let mut stream = TwoPhasedAtpStream::new(42, StreamDirection::Inbound);

            assert!(matches!(
                stream.reserve_send().await,
                Err(AtpStreamError::InvalidState(_))
            ));
        });
    }
