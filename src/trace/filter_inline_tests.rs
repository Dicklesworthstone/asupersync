    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    // Simple test event for filter testing
    struct TestEvent {
        kind: EventCategory,
        task: Option<TaskId>,
        region: Option<RegionId>,
    }

    impl FilterableEvent for TestEvent {
        fn event_kind(&self) -> EventCategory {
            self.kind
        }

        fn task_id(&self) -> Option<TaskId> {
            self.task
        }

        fn region_id(&self) -> Option<RegionId> {
            self.region
        }
    }

    fn make_task_id(index: u32) -> TaskId {
        TaskId::new_for_test(index, 0)
    }

    fn make_region_id(index: u32) -> RegionId {
        RegionId::new_for_test(index, 0)
    }

    #[test]
    fn default_filter_passes_all() {
        let mut filter = TraceFilter::default();
        assert!(filter.is_pass_through());

        let event = TestEvent {
            kind: EventCategory::Scheduling,
            task: Some(make_task_id(1)),
            region: Some(make_region_id(0)),
        };
        assert!(filter.should_record(&event));
    }

    #[test]
    fn include_kinds_filter() {
        let mut filter =
            TraceFilter::new().include_kinds([EventCategory::Scheduling, EventCategory::Time]);

        let scheduling = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: None,
        };
        let io = TestEvent {
            kind: EventCategory::Io,
            task: None,
            region: None,
        };

        assert!(filter.should_record(&scheduling));
        assert!(!filter.should_record(&io));
    }

    #[test]
    fn exclude_kinds_filter() {
        let mut filter = TraceFilter::new().exclude_kind(EventCategory::Rng);

        let rng = TestEvent {
            kind: EventCategory::Rng,
            task: None,
            region: None,
        };
        let scheduling = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: None,
        };

        assert!(!filter.should_record(&rng));
        assert!(filter.should_record(&scheduling));
    }

    #[test]
    fn exclude_takes_precedence_over_include() {
        let mut filter = TraceFilter::new()
            .include_kinds([EventCategory::Scheduling, EventCategory::Rng])
            .exclude_kind(EventCategory::Rng);

        let rng = TestEvent {
            kind: EventCategory::Rng,
            task: None,
            region: None,
        };
        assert!(!filter.should_record(&rng));
    }

    #[test]
    fn task_filter() {
        let task1 = make_task_id(1);
        let task2 = make_task_id(2);

        let mut filter = TraceFilter::new().filter_tasks([task1]);

        let event1 = TestEvent {
            kind: EventCategory::Scheduling,
            task: Some(task1),
            region: None,
        };
        let event2 = TestEvent {
            kind: EventCategory::Scheduling,
            task: Some(task2),
            region: None,
        };
        let no_task = TestEvent {
            kind: EventCategory::Time,
            task: None,
            region: None,
        };

        assert!(filter.should_record(&event1));
        assert!(!filter.should_record(&event2));
        assert!(filter.should_record(&no_task)); // No task = passes through
    }

    #[test]
    fn region_filter() {
        let region1 = make_region_id(1);
        let region2 = make_region_id(2);

        let mut filter = TraceFilter::new().filter_regions([region1]);

        let event1 = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: Some(region1),
        };
        let event2 = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: Some(region2),
        };
        let no_region = TestEvent {
            kind: EventCategory::Time,
            task: None,
            region: None,
        };

        assert!(filter.should_record(&event1));
        assert!(!filter.should_record(&event2));
        assert!(filter.should_record(&no_region)); // No region = passes through
    }

    #[test]
    fn exclude_region_blocks_events() {
        let region1 = make_region_id(1);
        let region2 = make_region_id(2);

        let mut filter = TraceFilter::new().exclude_region(region1);

        let excluded = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: Some(region1),
        };
        let allowed = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: Some(region2),
        };

        assert!(!filter.should_record(&excluded));
        assert!(filter.should_record(&allowed));
        assert!(filter.excluded_regions().contains(&region1));
    }

    #[test]
    fn exclude_region_overrides_region_filter() {
        let region1 = make_region_id(1);
        let region2 = make_region_id(2);

        let mut filter = TraceFilter::new()
            .filter_regions([region1, region2])
            .exclude_region(region2);

        let event1 = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: Some(region1),
        };
        let event2 = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: Some(region2),
        };

        assert!(filter.should_record(&event1));
        assert!(!filter.should_record(&event2));
    }

    #[test]
    fn sampling() {
        // Seed for reproducibility
        let mut filter = TraceFilter::new()
            .with_sample_rate(0.5)
            .with_sample_seed(42);

        // Count how many RNG events pass
        let mut passed = 0;
        let total = 1000;

        for _ in 0..total {
            let event = TestEvent {
                kind: EventCategory::Rng, // High-frequency, subject to sampling
                task: None,
                region: None,
            };
            if filter.should_record(&event) {
                passed += 1;
            }
        }

        // Should be approximately 50% (with some variance)
        assert!(passed > 400 && passed < 600, "Passed: {passed}");
    }

    #[test]
    fn no_sampling_for_non_high_frequency() {
        let mut filter = TraceFilter::new()
            .with_sample_rate(0.0) // Would drop all sampled events
            .with_sample_seed(42);

        // Scheduling is not high-frequency, so not sampled
        let event = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: None,
        };

        // Should pass even with 0% sample rate
        assert!(filter.should_record(&event));
    }

    #[test]
    fn custom_predicate() {
        let mut filter = TraceFilter::new().with_custom(|event| {
            // Only allow events with a task ID
            event.task_id().is_some()
        });

        let with_task = TestEvent {
            kind: EventCategory::Scheduling,
            task: Some(make_task_id(1)),
            region: None,
        };
        let without_task = TestEvent {
            kind: EventCategory::Time,
            task: None,
            region: None,
        };

        assert!(filter.should_record(&with_task));
        assert!(!filter.should_record(&without_task));
    }

    #[test]
    fn predefined_scheduling_only() {
        let filter = TraceFilter::scheduling_only();

        assert!(filter.includes_kind(EventCategory::Scheduling));
        assert!(filter.includes_kind(EventCategory::Chaos));
        assert!(!filter.includes_kind(EventCategory::Rng));
        assert!(!filter.includes_kind(EventCategory::Io));
    }

    #[test]
    fn predefined_no_rng() {
        let filter = TraceFilter::no_rng();

        assert!(!filter.includes_kind(EventCategory::Rng));
        assert!(filter.includes_kind(EventCategory::Scheduling));
        assert!(filter.includes_kind(EventCategory::Time));
    }

    #[test]
    fn predefined_io_focused() {
        let filter = TraceFilter::io_focused();

        assert!(filter.includes_kind(EventCategory::Io));
        assert!(filter.includes_kind(EventCategory::Scheduling));
        assert!(filter.includes_kind(EventCategory::Time));
        assert!(!filter.includes_kind(EventCategory::Rng));
        assert!(!filter.includes_kind(EventCategory::Waker));
    }

    #[test]
    fn filter_builder() {
        let filter = FilterBuilder::new()
            .include_kinds([EventCategory::Scheduling, EventCategory::Time])
            .exclude_kinds([EventCategory::Waker])
            .sample_rate(0.5)
            .build();

        assert!(filter.includes_kind(EventCategory::Scheduling));
        assert!(!filter.includes_kind(EventCategory::Rng));
        assert!(!filter.includes_kind(EventCategory::Waker));
        assert!((filter.sample_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn filter_builder_exclude_root_region() {
        let mut filter = FilterBuilder::new().exclude_root_region().build();
        let root = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: Some(make_region_id(0)),
        };
        let non_root = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: Some(make_region_id(7)),
        };

        assert!(!filter.should_record(&root));
        assert!(filter.should_record(&non_root));
    }

    #[test]
    fn is_pass_through() {
        assert!(TraceFilter::default().is_pass_through());
        assert!(!TraceFilter::no_rng().is_pass_through());
        assert!(!TraceFilter::scheduling_only().is_pass_through());
        assert!(!TraceFilter::with_sampling(0.5).is_pass_through());
    }
