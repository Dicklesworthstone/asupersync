    use super::*;
    use crate::bytes::Bytes;

    #[test]
    fn test_reassembly_in_order() {
        let mut buffer = ReassemblyBuffer::new(10000);

        let segment1 = DataSegment::new(0, Bytes::from("hello"), false);
        let segment2 = DataSegment::new(5, Bytes::from("world"), true);

        let result1 = buffer.insert_segment(segment1).unwrap(); // ubs:ignore - test oracle
        assert_eq!(result1.len(), 1);
        assert_eq!(&result1[0][..], b"hello");

        let result2 = buffer.insert_segment(segment2).unwrap(); // ubs:ignore - test oracle
        assert_eq!(result2.len(), 1);
        assert_eq!(&result2[0][..], b"world");

        assert!(buffer.is_complete());
        assert_eq!(buffer.final_size(), Some(10));
    }

    #[test]
    fn test_reassembly_out_of_order() {
        let mut buffer = ReassemblyBuffer::new(10000);

        // Insert segments out of order
        let segment2 = DataSegment::new(5, Bytes::from("world"), true);
        let segment1 = DataSegment::new(0, Bytes::from("hello"), false);

        // Second segment first - should be buffered
        let result1 = buffer.insert_segment(segment2).unwrap(); // ubs:ignore - test oracle
        assert_eq!(result1.len(), 0); // Nothing deliverable yet

        // First segment - should deliver both
        let result2 = buffer.insert_segment(segment1).unwrap(); // ubs:ignore - test oracle
        assert_eq!(result2.len(), 2);
        assert_eq!(&result2[0][..], b"hello");
        assert_eq!(&result2[1][..], b"world");

        assert!(buffer.is_complete());
    }

    #[test]
    fn test_final_size_mismatch() {
        let mut buffer = ReassemblyBuffer::new(10000);

        let segment1 = DataSegment::new(0, Bytes::from("hello"), true);
        let segment2 = DataSegment::new(5, Bytes::from("world"), true);

        buffer.insert_segment(segment1).unwrap(); // ubs:ignore - test oracle

        // This should fail due to final size mismatch
        let result = buffer.insert_segment(segment2);
        assert!(result.is_err());
    }

    #[test]
    fn test_overlapping_segments() {
        let mut buffer = ReassemblyBuffer::new(10000);

        let segment1 = DataSegment::new(5, Bytes::from("world"), false);
        let duplicate_overlap = DataSegment::new(7, Bytes::from("rld"), false);
        let conflicting_overlap = DataSegment::new(6, Bytes::from("XX"), false);

        buffer.insert_segment(segment1).unwrap(); // ubs:ignore - test oracle

        // Duplicate overlapping bytes are harmless retransmissions.
        let duplicate = buffer.insert_segment(duplicate_overlap).unwrap(); // ubs:ignore - test oracle
        assert!(duplicate.is_empty());

        // Conflicting buffered bytes must fail closed.
        let result = buffer.insert_segment(conflicting_overlap);
        assert!(result.is_err());
    }

    #[test]
    fn test_buffer_limit() {
        let mut buffer = ReassemblyBuffer::new(10); // Very small limit

        let large_segment = DataSegment::new(0, Bytes::from("this is too large"), false);

        let result = buffer.insert_segment(large_segment);
        assert!(result.is_err());
    }

    #[test]
    fn byte_limit_does_not_block_receive_head() {
        let mut buffer = ReassemblyBuffer::new(4);
        assert!(
            buffer
                .insert_segment(DataSegment::new(2, Bytes::from_static(b"tail"), false))
                .expect("fill retained byte budget behind a gap")
                .is_empty()
        );
        assert_eq!(buffer.buffered_data_size(), 4);

        let head = buffer
            .insert_segment(DataSegment::new(0, Bytes::from_static(b"h"), false))
            .expect("receive-head data must remain admissible at the byte cap");
        assert_eq!(head, vec![Bytes::from_static(b"h")]);
        assert_eq!(buffer.buffered_data_size(), 4);

        let drained = buffer
            .insert_segment(DataSegment::new(1, Bytes::from_static(b"i"), false))
            .expect("closing the head gap must drain its retained successor");
        assert_eq!(
            drained,
            vec![Bytes::from_static(b"i"), Bytes::from_static(b"tail")]
        );
        assert_eq!(buffer.buffered_data_size(), 0);
        assert_eq!(buffer.next_expected_offset(), 6);
    }

    #[test]
    fn fragment_count_limit_rejects_before_mutating_reassembly_state() {
        let mut buffer = ReassemblyBuffer::new(1 << 20);

        for fragment in 0..MAX_BUFFERED_REASSEMBLY_SEGMENTS {
            let offset = 1 + (fragment as u64 * 2);
            let delivered = buffer
                .insert_segment(DataSegment::new(offset, Bytes::from_static(b"x"), false))
                .unwrap(); // ubs:ignore - test oracle
            assert!(delivered.is_empty());
        }
        assert_eq!(buffer.buffered_segments(), MAX_BUFFERED_REASSEMBLY_SEGMENTS);
        assert_eq!(
            buffer.buffered_data_size(),
            MAX_BUFFERED_REASSEMBLY_SEGMENTS as u64
        );

        let rejected = buffer.insert_segment(DataSegment::new(
            1 + (MAX_BUFFERED_REASSEMBLY_SEGMENTS as u64 * 2),
            Bytes::from_static(b"x"),
            false,
        ));
        assert!(matches!(
            rejected,
            Outcome::Err(StreamError::ConnectionError { ref reason })
                if reason == "Reassembly segment limit exceeded"
        ));
        assert_eq!(buffer.buffered_segments(), MAX_BUFFERED_REASSEMBLY_SEGMENTS);
        assert_eq!(
            buffer.buffered_data_size(),
            MAX_BUFFERED_REASSEMBLY_SEGMENTS as u64
        );

        let delivered = buffer
            .insert_segment(DataSegment::new(0, Bytes::from_static(b"x"), false))
            .expect("head-of-line fragment must remain admissible at the metadata cap");
        assert_eq!(
            delivered,
            vec![Bytes::from_static(b"x"), Bytes::from_static(b"x")]
        );
        assert_eq!(
            buffer.buffered_segments(),
            MAX_BUFFERED_REASSEMBLY_SEGMENTS - 1,
            "filling the head gap must reduce retained metadata"
        );
    }

    #[test]
    fn rejected_final_segment_does_not_poison_final_size() {
        let mut buffer = ReassemblyBuffer::new(4);

        let rejected_final = DataSegment::new(5, Bytes::from("final"), true);
        let rejected = buffer.insert_segment(rejected_final);
        assert!(rejected.is_err());
        assert_eq!(buffer.final_size(), None);
        assert!(!buffer.received_final_segment());

        let accepted_final = DataSegment::new(0, Bytes::from("ok"), true);
        let delivered = buffer.insert_segment(accepted_final).unwrap(); // ubs:ignore - test oracle
        assert_eq!(delivered.len(), 1);
        assert_eq!(&delivered[0][..], b"ok");
        assert_eq!(buffer.final_size(), Some(2));
        assert!(buffer.received_final_segment());
        assert!(buffer.is_complete());
    }

    #[test]
    fn conflicting_final_overlap_does_not_poison_final_size() {
        let mut buffer = ReassemblyBuffer::new(10000);

        let buffered = DataSegment::new(5, Bytes::from("world"), false);
        buffer.insert_segment(buffered).unwrap(); // ubs:ignore - test oracle

        let conflicting_final = DataSegment::new(5, Bytes::from("WORLD"), true);
        let rejected = buffer.insert_segment(conflicting_final);
        assert!(rejected.is_err());
        assert_eq!(buffer.final_size(), None);
        assert!(!buffer.received_final_segment());

        let matching_final = DataSegment::new(5, Bytes::from("world"), true);
        let duplicate = buffer.insert_segment(matching_final).unwrap(); // ubs:ignore - test oracle
        assert!(duplicate.is_empty());
        assert_eq!(buffer.final_size(), Some(10));
        assert!(buffer.received_final_segment());

        let prefix = DataSegment::new(0, Bytes::from("hello"), false);
        let delivered = buffer.insert_segment(prefix).unwrap(); // ubs:ignore - test oracle
        assert_eq!(delivered.len(), 2);
        assert_eq!(&delivered[0][..], b"hello");
        assert_eq!(&delivered[1][..], b"world");
        assert!(buffer.is_complete());
    }

    #[test]
    fn data_beyond_known_final_size_is_rejected_without_mutation() {
        let mut buffer = ReassemblyBuffer::new(10000);
        assert!(
            buffer
                .insert_segment(DataSegment::new(5, Bytes::from_static(b"world"), true))
                .expect("out-of-order final segment")
                .is_empty()
        );
        assert_eq!(buffer.final_size(), Some(10));
        assert_eq!(buffer.buffered_data_size(), 5);

        let rejected = buffer.insert_segment(DataSegment::new(10, Bytes::from_static(b"!"), false));
        assert!(matches!(
            rejected,
            Outcome::Err(StreamError::FinalSizeMismatch {
                expected: 10,
                actual: 11,
                ..
            })
        ));
        assert_eq!(buffer.final_size(), Some(10));
        assert_eq!(buffer.buffered_data_size(), 5);
        assert_eq!(buffer.buffered_segments(), 1);
    }

    #[test]
    fn final_size_below_buffered_data_is_rejected_without_mutation() {
        let mut buffer = ReassemblyBuffer::new(10000);
        assert!(
            buffer
                .insert_segment(DataSegment::new(10, Bytes::from_static(b"world"), false))
                .expect("buffer data above the receive head")
                .is_empty()
        );

        let rejected =
            buffer.insert_segment(DataSegment::new(0, Bytes::from_static(b"hello"), true));
        assert!(matches!(
            rejected,
            Outcome::Err(StreamError::FinalSizeMismatch {
                expected: 15,
                actual: 5,
                ..
            })
        ));
        assert_eq!(buffer.final_size(), None);
        assert!(!buffer.received_final_segment());
        assert_eq!(buffer.buffered_data_size(), 5);
        assert_eq!(buffer.buffered_segments(), 1);
    }

    #[test]
    fn duplicate_delivered_fin_establishes_completion() {
        let mut buffer = ReassemblyBuffer::new(10000);
        assert_eq!(
            buffer
                .insert_segment(DataSegment::new(0, Bytes::from_static(b"hello"), false))
                .expect("deliver data without FIN"),
            vec![Bytes::from_static(b"hello")]
        );
        assert!(!buffer.is_complete());

        assert!(
            buffer
                .insert_segment(DataSegment::new(0, Bytes::from_static(b"hello"), true))
                .expect("duplicate retransmission carries FIN")
                .is_empty()
        );
        assert_eq!(buffer.final_size(), Some(5));
        assert!(buffer.received_final_segment());
        assert!(buffer.is_complete());
    }

    #[test]
    fn segment_offset_overflow_is_rejected() {
        let mut buffer = ReassemblyBuffer::new(10000);

        let overflowing = DataSegment::new(u64::MAX - 1, Bytes::from_static(b"abcd"), false);
        let result = buffer.insert_segment(overflowing);

        assert!(result.is_err());
        assert_eq!(buffer.next_expected_offset(), 0);
        assert_eq!(buffer.buffered_segments(), 0);
        assert_eq!(buffer.buffered_data_size(), 0);
        assert_eq!(buffer.final_size(), None);
        assert!(!buffer.received_final_segment());
    }
