    use super::*;

    #[test]
    fn test_stream_scheduler_priority_ordering() {
        let mut scheduler = StreamScheduler::new();

        let control_stream = StreamId::new(0);
        let data_stream = StreamId::new(4);
        let repair_stream = StreamId::new(8);

        scheduler.register_stream(repair_stream, StreamPriority::Repair);
        scheduler.register_stream(data_stream, StreamPriority::Data);
        scheduler.register_stream(control_stream, StreamPriority::Control);

        // Control should come first (highest priority)
        assert_eq!(scheduler.next_stream(), Some(control_stream));
        scheduler.mark_blocked(control_stream);

        // With control blocked, data should come next.
        assert_eq!(scheduler.next_stream(), Some(data_stream));
        scheduler.mark_blocked(data_stream);

        // With higher-priority streams blocked, repair should come last.
        assert_eq!(scheduler.next_stream(), Some(repair_stream));
    }

    #[test]
    fn test_stream_scheduler_round_robin_within_priority() {
        let mut scheduler = StreamScheduler::new();

        let data1 = StreamId::new(4);
        let data2 = StreamId::new(8);
        let data3 = StreamId::new(12);

        scheduler.register_stream(data1, StreamPriority::Data);
        scheduler.register_stream(data2, StreamPriority::Data);
        scheduler.register_stream(data3, StreamPriority::Data);

        // Should round-robin between data streams
        let first = scheduler.next_stream().unwrap(); // ubs:ignore - test oracle
        let second = scheduler.next_stream().unwrap(); // ubs:ignore - test oracle
        let third = scheduler.next_stream().unwrap(); // ubs:ignore - test oracle

        // All streams should be different
        assert_ne!(first, second);
        assert_ne!(second, third);
        assert_ne!(first, third);
    }

    #[test]
    fn test_stream_unregister() {
        let mut scheduler = StreamScheduler::new();

        let stream1 = StreamId::new(0);
        let stream2 = StreamId::new(4);

        scheduler.register_stream(stream1, StreamPriority::Control);
        scheduler.register_stream(stream2, StreamPriority::Control);

        scheduler.unregister_stream(stream1);

        assert_eq!(scheduler.next_stream(), Some(stream2));
        assert_eq!(scheduler.next_stream(), Some(stream2));
        assert_eq!(scheduler.stream_count(), 1);
    }

    #[test]
    fn test_blocked_streams_are_not_scheduled() {
        let mut scheduler = StreamScheduler::new();

        let data1 = StreamId::new(4);
        let data2 = StreamId::new(8);
        let data3 = StreamId::new(12);

        scheduler.register_stream(data1, StreamPriority::Data);
        scheduler.register_stream(data2, StreamPriority::Data);
        scheduler.register_stream(data3, StreamPriority::Data);
        scheduler.mark_blocked(data2);

        assert_eq!(scheduler.next_stream(), Some(data1));
        assert_eq!(scheduler.next_stream(), Some(data3));
        assert_eq!(scheduler.next_stream(), Some(data1));
    }

    #[test]
    fn test_ready_unblocks_higher_priority_stream() {
        let mut scheduler = StreamScheduler::new();

        let control = StreamId::new(0);
        let data = StreamId::new(4);

        scheduler.register_stream(control, StreamPriority::Control);
        scheduler.register_stream(data, StreamPriority::Data);
        scheduler.mark_blocked(control);

        assert_eq!(scheduler.next_stream(), Some(data));

        scheduler.mark_ready(control);
        assert_eq!(scheduler.next_stream(), Some(control));
    }

    #[test]
    fn test_starvation_protection_yields_after_control_burst() {
        let mut scheduler = StreamScheduler::new();

        let control = StreamId::new(0);
        let data = StreamId::new(4);
        let repair = StreamId::new(8);

        scheduler.register_stream(control, StreamPriority::Control);
        scheduler.register_stream(data, StreamPriority::Data);
        scheduler.register_stream(repair, StreamPriority::Repair);

        for _ in 0..MAX_STRICT_PRIORITY_BURST {
            assert_eq!(scheduler.next_stream(), Some(control));
        }

        assert_eq!(scheduler.next_stream(), Some(data));
        assert_eq!(scheduler.next_stream(), Some(control));
    }

    #[test]
    fn test_all_blocked_streams_report_no_ready_work() {
        let mut scheduler = StreamScheduler::new();

        let control = StreamId::new(0);
        let data = StreamId::new(4);

        scheduler.register_stream(control, StreamPriority::Control);
        scheduler.register_stream(data, StreamPriority::Data);
        scheduler.mark_blocked(control);
        scheduler.mark_blocked(data);

        assert!(!scheduler.has_ready_streams());
        assert_eq!(scheduler.stream_count(), 2);
        assert_eq!(scheduler.next_stream(), None);

        let stats = scheduler.statistics();
        assert_eq!(stats.control_queued, 0);
        assert_eq!(stats.data_queued, 0);
    }
