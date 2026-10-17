    use super::*;

    fn test_content(
        id: u64,
        priority: PriorityClass,
        size: usize,
        cost: f64,
        utility: f64,
    ) -> ContentItem {
        ContentItem::new(ContentId::new(id), priority, size, cost, utility)
    }

    #[test]
    fn priority_class_ordering() {
        assert!(PriorityClass::Control > PriorityClass::Data);
        assert!(PriorityClass::Data > PriorityClass::Telemetry);
        assert!(PriorityClass::Control.is_control_plane());
        assert!(PriorityClass::Data.is_data_plane());
    }

    #[test]
    fn content_scheduler_basic_operation() {
        let mut scheduler = ContentScheduler::new();

        // Schedule items with different priorities
        let control = test_content(1, PriorityClass::Control, 100, 1.0, 10.0);
        let data = test_content(2, PriorityClass::Data, 1000, 2.0, 5.0);
        let telemetry = test_content(3, PriorityClass::Telemetry, 50, 0.5, 1.0);

        assert!(scheduler.schedule(data.clone()));
        assert!(scheduler.schedule(telemetry.clone()));
        assert!(scheduler.schedule(control.clone()));

        assert_eq!(scheduler.pending_count(), 3);

        // Should pop control first (highest priority)
        let (next_item, evidence) = scheduler.next_content(Time::ZERO).unwrap();
        assert_eq!(next_item.id, control.id);
        assert_eq!(evidence.reason, ScheduleReason::PriorityClass);
        assert_eq!(evidence.selected, control.id);

        // Then data (higher efficiency than telemetry: 2.5 vs 2.0)
        let (next_item, _) = scheduler.next_content(Time::ZERO).unwrap();
        assert_eq!(next_item.id, data.id);

        // Finally telemetry
        let (next_item, _) = scheduler.next_content(Time::ZERO).unwrap();
        assert_eq!(next_item.id, telemetry.id);

        assert!(!scheduler.has_pending_content());
    }

    #[test]
    fn content_scheduler_fifo_ordering() {
        let mut scheduler = ContentScheduler::new();

        // Schedule items with same priority and efficiency
        let item1 = test_content(1, PriorityClass::Data, 100, 1.0, 2.0);
        let item2 = test_content(2, PriorityClass::Data, 100, 1.0, 2.0);

        scheduler.schedule(item1.clone());
        scheduler.schedule(item2.clone());

        // Should maintain FIFO order for ties
        let (next_item, evidence) = scheduler.next_content(Time::ZERO).unwrap();
        assert_eq!(next_item.id, item1.id);
        assert_eq!(evidence.reason, ScheduleReason::FifoOrder);

        let (next_item, _) = scheduler.next_content(Time::ZERO).unwrap();
        assert_eq!(next_item.id, item2.id);
    }

    #[test]
    fn content_scheduler_unschedule() {
        let mut scheduler = ContentScheduler::new();

        let item = test_content(1, PriorityClass::Data, 100, 1.0, 2.0);
        scheduler.schedule(item.clone());

        assert_eq!(scheduler.pending_count(), 1);

        assert!(scheduler.unschedule(item.id));
        assert_eq!(scheduler.pending_count(), 0);

        // Should not find any content
        assert!(scheduler.next_content(Time::ZERO).is_none());
    }

    #[test]
    fn content_scheduler_duplicate_schedule() {
        let mut scheduler = ContentScheduler::new();

        let item = test_content(1, PriorityClass::Data, 100, 1.0, 2.0);

        assert!(scheduler.schedule(item.clone()));
        assert!(!scheduler.schedule(item.clone())); // Duplicate should return false

        assert_eq!(scheduler.pending_count(), 1);
    }

    #[test]
    fn content_scheduler_reschedule_after_unschedule_delivers_new_item() {
        let mut scheduler = ContentScheduler::new();

        // Old incarnation sorts strictly higher (Control beats Data), so the
        // stale heap entry would be popped first if liveness were keyed on the
        // content ID alone instead of (ID, generation).
        let old = test_content(1, PriorityClass::Control, 100, 1.0, 10.0);
        scheduler.schedule(old);
        assert!(scheduler.unschedule(ContentId::new(1)));

        let new = test_content(1, PriorityClass::Data, 200, 2.0, 4.0);
        assert!(scheduler.schedule(new.clone()));
        assert_eq!(scheduler.pending_count(), 1);

        let (item, _) = scheduler.next_content(Time::ZERO).unwrap();
        assert_eq!(item.id, new.id);
        assert_eq!(item.priority_class, PriorityClass::Data);
        assert_eq!(item.size_bytes, 200);
        assert!(!scheduler.has_pending_content());
        assert!(scheduler.next_content(Time::ZERO).is_none());
    }

    #[test]
    fn scheduled_content_eq_is_consistent_with_ord() {
        // Same ID, different generation: previously `eq` returned true while
        // `cmp` returned non-equal, violating the Ord contract.
        let a = ScheduledContent {
            item: test_content(1, PriorityClass::Data, 100, 1.0, 2.0),
            generation: 0,
        };
        let b = ScheduledContent {
            item: test_content(1, PriorityClass::Data, 100, 1.0, 2.0),
            generation: 1,
        };
        assert_ne!(a, b);
        assert_ne!(a.cmp(&b), std::cmp::Ordering::Equal);

        let c = ScheduledContent {
            item: test_content(1, PriorityClass::Data, 100, 1.0, 2.0),
            generation: 0,
        };
        assert_eq!(a, c);
        assert_eq!(a.cmp(&c), std::cmp::Ordering::Equal);
    }

    #[test]
    fn pressure_snapshot_analysis() {
        let mut pressure = PressureSnapshot::default();
        assert!(!pressure.has_high_pressure());
        assert_eq!(pressure.max_pressure(), 0.0);

        pressure.network = 0.9;
        assert!(pressure.has_high_pressure());
        assert!(pressure.network_dominant());
        assert_eq!(pressure.max_pressure(), 0.9);
    }

    #[test]
    fn content_item_efficiency_calculation() {
        let efficient = test_content(1, PriorityClass::Data, 100, 1.0, 10.0);
        let inefficient = test_content(2, PriorityClass::Data, 100, 5.0, 10.0);

        assert_eq!(efficient.efficiency_ratio(), 10.0);
        assert_eq!(inefficient.efficiency_ratio(), 2.0);
        assert!(efficient.efficiency_ratio() > inefficient.efficiency_ratio());
    }
