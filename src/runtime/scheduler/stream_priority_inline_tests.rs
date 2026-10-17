    use super::*;
    use crate::runtime::scheduler::content::{ContentId, ContentItem};

    fn test_content(id: u64, priority: PriorityClass, size: usize) -> ContentItem {
        ContentItem::new(ContentId::new(id), priority, size, 1.0, 1.0)
    }

    #[test]
    fn stream_priority_mapping() {
        assert_eq!(
            StreamPriority::from_content_class(PriorityClass::Control),
            StreamPriority::Critical
        );
        assert_eq!(
            StreamPriority::from_content_class(PriorityClass::Data),
            StreamPriority::Normal
        );
        assert_eq!(
            StreamPriority::from_content_class(PriorityClass::Telemetry),
            StreamPriority::Background
        );
    }

    #[test]
    fn stream_assignment_basic() {
        let mut scheduler = StreamPriorityScheduler::new(10);
        let content = test_content(1, PriorityClass::Control, 100);

        let assignment = scheduler.assign_stream(&content, Time::ZERO);

        assert_eq!(assignment.stream_id, 1);
        assert_eq!(assignment.priority, StreamPriority::Critical);
        assert_eq!(scheduler.active_stream_count(), 1);
    }

    #[test]
    fn stream_reuse() {
        let mut scheduler = StreamPriorityScheduler::new(2);

        let content1 = test_content(1, PriorityClass::Control, 100);
        let assignment1 = scheduler.assign_stream(&content1, Time::ZERO);

        // Release the stream
        scheduler.release_stream(assignment1.stream_id, Time::from_nanos(100));

        // Assign new content with same priority - should reuse stream
        let content2 = test_content(2, PriorityClass::Control, 200);
        let assignment2 = scheduler.assign_stream(&content2, Time::from_nanos(200));

        assert_eq!(assignment1.stream_id, assignment2.stream_id);
        assert_eq!(assignment2.priority, StreamPriority::Critical);
    }

    #[test]
    fn integrated_scheduler_basic() {
        let mut integrated = SchedulerIntegration::new();

        let content = test_content(1, PriorityClass::Data, 100);
        assert!(integrated.schedule_content(content, Time::ZERO));

        let stats = integrated.stats();
        assert_eq!(stats.pending_content_count, 1);
        assert_eq!(stats.active_stream_count, 1);

        let result = integrated.next_content(Time::ZERO);
        assert!(result.is_some());

        let (content, assignment, _evidence) = result.unwrap();
        assert_eq!(content.id.value(), 1);
        assert_eq!(assignment.priority, StreamPriority::Normal);
    }

    #[test]
    fn reuse_scan_retains_other_priority_lanes() {
        let mut scheduler = StreamPriorityScheduler::new(10);

        // Allocate one stream per lane, then release both.
        let critical =
            scheduler.assign_stream(&test_content(1, PriorityClass::Control, 10), Time::ZERO);
        let normal = scheduler.assign_stream(
            &test_content(2, PriorityClass::Data, 10),
            Time::from_nanos(1),
        );
        scheduler.release_stream(critical.stream_id, Time::from_nanos(10));
        scheduler.release_stream(normal.stream_id, Time::from_nanos(20));

        // A Normal allocation scans past the Critical candidate; the Critical
        // entry must survive the scan instead of being silently dropped.
        let normal2 = scheduler.assign_stream(
            &test_content(3, PriorityClass::Data, 10),
            Time::from_nanos(30),
        );
        assert_eq!(normal2.stream_id, normal.stream_id);

        let critical2 = scheduler.assign_stream(
            &test_content(4, PriorityClass::Control, 10),
            Time::from_nanos(40),
        );
        assert_eq!(
            critical2.stream_id, critical.stream_id,
            "non-matching candidates must stay in the available pool"
        );
    }

    #[test]
    fn pool_trim_keeps_most_preferred_candidates() {
        // keep = max_concurrent_streams / 2 = 2.
        let mut scheduler = StreamPriorityScheduler::new(4);

        let critical =
            scheduler.assign_stream(&test_content(1, PriorityClass::Control, 10), Time::ZERO);
        let normal = scheduler.assign_stream(
            &test_content(2, PriorityClass::Data, 10),
            Time::from_nanos(1),
        );
        let background = scheduler.assign_stream(
            &test_content(3, PriorityClass::Telemetry, 10),
            Time::from_nanos(2),
        );

        scheduler.release_stream(critical.stream_id, Time::from_nanos(10));
        scheduler.release_stream(normal.stream_id, Time::from_nanos(20));
        // Third release exceeds the pool limit and must evict the LEAST
        // preferred candidate (Background), not the most preferred (Critical).
        scheduler.release_stream(background.stream_id, Time::from_nanos(30));

        let critical2 = scheduler.assign_stream(
            &test_content(4, PriorityClass::Control, 10),
            Time::from_nanos(40),
        );
        assert_eq!(
            critical2.stream_id, critical.stream_id,
            "pool trim must keep the most preferred reuse candidates"
        );
    }

    #[test]
    fn stream_usage_tracking() {
        let mut scheduler = StreamPriorityScheduler::new(10);

        let content1 = test_content(1, PriorityClass::Data, 100);
        let content2 = test_content(2, PriorityClass::Data, 200);

        let assignment1 = scheduler.assign_stream(&content1, Time::ZERO);
        let assignment2 = scheduler.assign_stream(&content2, Time::from_nanos(100));

        // Both should use the same stream (same priority)
        assert_eq!(assignment1.stream_id, assignment2.stream_id);

        let usage = scheduler.stream_usage(assignment1.stream_id).unwrap();
        assert_eq!(usage.bytes_sent, 300); // 100 + 200
        assert_eq!(usage.items_sent, 2);
    }
