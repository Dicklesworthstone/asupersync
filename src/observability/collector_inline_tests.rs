    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn test_collector_captures_logs() {
        let collector = LogCollector::new(10).with_min_level(LogLevel::Debug);
        collector.log(LogEntry::info("test"));
        assert_eq!(collector.len(), 1);
        assert_eq!(collector.peek()[0].message(), "test");
    }

    #[test]
    fn test_collector_respects_level_filter() {
        let collector = LogCollector::new(10).with_min_level(LogLevel::Warn);
        collector.log(LogEntry::info("ignored"));
        collector.log(LogEntry::warn("captured"));
        assert_eq!(collector.len(), 1);
        assert_eq!(collector.peek()[0].message(), "captured");
    }

    #[test]
    fn test_collector_buffer_capacity() {
        let collector = LogCollector::new(2);
        collector.log(LogEntry::info("1"));
        collector.log(LogEntry::info("2"));
        collector.log(LogEntry::info("3")); // Should evict 1

        let entries = collector.peek();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message(), "2");
        assert_eq!(entries[1].message(), "3");
    }

    #[test]
    fn test_collector_zero_capacity_drops_logs() {
        let collector = LogCollector::new(0);
        collector.log(LogEntry::info("dropped"));

        assert_eq!(collector.capacity(), 0);
        assert!(collector.is_empty());
        assert!(collector.peek().is_empty());
    }

    #[test]
    fn test_collector_drain_clears() {
        let collector = LogCollector::new(10);
        collector.log(LogEntry::info("msg"));

        let drained = collector.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(collector.len(), 0);
    }

    #[test]
    fn test_collector_peek_does_not_clear() {
        let collector = LogCollector::new(10);
        collector.log(LogEntry::info("msg"));

        let peeked = collector.peek();
        assert_eq!(peeked.len(), 1);
        assert_eq!(collector.len(), 1);
    }

    #[test]
    fn test_collector_thread_safe() {
        let collector = LogCollector::new(100);
        let c1 = collector.clone();

        std::thread::spawn(move || {
            c1.log(LogEntry::info("thread"));
        })
        .join()
        .unwrap();

        assert_eq!(collector.len(), 1);
    }

    #[test]
    fn test_collector_clone_shares_min_level_configuration() {
        let collector = LogCollector::new(10).with_min_level(LogLevel::Error);
        let clone = collector.clone().with_min_level(LogLevel::Warn);

        assert_eq!(collector.min_level(), LogLevel::Warn);
        collector.log(LogEntry::warn("captured"));

        assert_eq!(clone.len(), 1);
        assert_eq!(clone.peek()[0].message(), "captured");
    }
