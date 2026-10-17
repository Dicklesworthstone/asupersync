    use super::*;
    use crate::atp::object::ContentId;

    #[test]
    fn replay_pointer_basic_operations() {
        let checksum = SerializableContentId::from(&ContentId::from_bytes(b"test-stream"));
        let pointer = AtpReplayPointer::new("stream-1", 100, 200, checksum.clone()); // ubs:ignore - test oracle clone

        assert_eq!(pointer.stream_id, "stream-1");
        assert_eq!(pointer.start_position, 100);
        assert_eq!(pointer.end_position, 200);
        assert_eq!(pointer.stream_checksum, checksum);
        assert_eq!(pointer.event_count(), 101);

        assert!(pointer.covers_position(150));
        assert!(!pointer.covers_position(50));
        assert!(!pointer.covers_position(250));

        pointer.validate().expect("basic pointer should be valid");
    }

    #[test]
    fn replay_pointer_validation() {
        let checksum = SerializableContentId::from(&ContentId::from_bytes(b"test"));

        // Invalid range
        let invalid_range = AtpReplayPointer::new("stream-1", 200, 100, checksum.clone());
        let err = invalid_range
            .validate()
            .expect_err("invalid range should fail");
        assert!(matches!(err, ReplayPointerError::InvalidRange { .. }));

        // Empty stream ID
        let mut empty_stream = AtpReplayPointer::new("stream-1", 100, 200, checksum);
        empty_stream.stream_id = String::new();
        let err = empty_stream
            .validate()
            .expect_err("empty stream ID should fail");
        assert!(matches!(err, ReplayPointerError::EmptyStreamId));
    }

    #[test]
    fn replay_event_filter_matching() {
        let filter = ReplayEventFilter::new()
            .include_kinds(vec![ReplayableEventKind::ChunkTransfer])
            .exclude_kinds(vec![ReplayableEventKind::Error])
            .timestamp_range(Some(1000), Some(2000));

        let chunk_event = ReplayableEvent {
            sequence: 1,
            timestamp_micros: 1500,
            kind: ReplayableEventKind::ChunkTransfer,
            payload: ReplayableEventPayload::ChunkTransfer {
                chunk_index: 0,
                chunk_size: 1024,
                chunk_digest: SerializableContentId::from(&ContentId::from_bytes(b"chunk")),
                success: true,
            },
            metadata: BTreeMap::new(),
        };

        let error_event = ReplayableEvent {
            sequence: 2,
            timestamp_micros: 1500,
            kind: ReplayableEventKind::Error,
            payload: ReplayableEventPayload::Error {
                error_category: "network".to_string(),
                error_code: "timeout".to_string(),
                error_message: "connection timeout".to_string(),
                recoverable: true,
            },
            metadata: BTreeMap::new(),
        };

        let old_event = ReplayableEvent {
            sequence: 3,
            timestamp_micros: 500, // Too old
            kind: ReplayableEventKind::ChunkTransfer,
            payload: ReplayableEventPayload::ChunkTransfer {
                chunk_index: 1,
                chunk_size: 1024,
                chunk_digest: SerializableContentId::from(&ContentId::from_bytes(b"chunk2")),
                success: true,
            },
            metadata: BTreeMap::new(),
        };

        assert!(filter.matches(&chunk_event));
        assert!(!filter.matches(&error_event)); // Excluded kind
        assert!(!filter.matches(&old_event)); // Outside timestamp range
    }

    #[test]
    fn replay_event_filter_validation() {
        // Invalid timestamp range
        let invalid_filter = ReplayEventFilter::new().timestamp_range(Some(2000), Some(1000));
        let err = invalid_filter
            .validate()
            .expect_err("invalid timestamp range should fail");
        assert!(matches!(
            err,
            ReplayPointerError::InvalidTimestampRange { .. }
        ));

        // Valid filter
        let valid_filter = ReplayEventFilter::new().timestamp_range(Some(1000), Some(2000));
        valid_filter.validate().expect("valid filter should pass");
    }

    #[test]
    fn replayable_event_kind_properties() {
        assert_eq!(
            ReplayableEventKind::ChunkTransfer.as_str(),
            "chunk_transfer"
        );
        assert!(ReplayableEventKind::SessionStart.is_critical());
        assert!(ReplayableEventKind::Error.is_critical());
        assert!(!ReplayableEventKind::PeerAuth.is_critical());
    }

    #[test]
    fn replay_pointer_with_context_and_filter() {
        let checksum = SerializableContentId::from(&ContentId::from_bytes(b"test-stream"));
        let filter =
            ReplayEventFilter::new().include_kinds(vec![ReplayableEventKind::ChunkTransfer]);

        let pointer = AtpReplayPointer::new("stream-1", 100, 200, checksum)
            .with_filter(filter)
            .with_context("session_id", "test-session")
            .with_context("peer_id", "peer-123");

        assert!(pointer.event_filter.is_some());
        assert_eq!(
            pointer.context.get("session_id"),
            Some(&"test-session".to_string())
        );
        assert_eq!(
            pointer.context.get("peer_id"),
            Some(&"peer-123".to_string())
        );

        pointer
            .validate()
            .expect("pointer with context and filter should be valid");
    }
