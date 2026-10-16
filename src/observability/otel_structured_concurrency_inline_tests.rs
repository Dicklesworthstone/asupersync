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
    fn config_default_values() {
        let config = OtelStructuredConcurrencyConfig::default();
        assert_eq!(config.global_sample_rate, 0.1);
        assert!(config.always_sample.contains(&SpanType::Cancel));
        assert_eq!(config.max_active_spans, 10_000);
        assert_eq!(config.lazy_threshold, 5);
    }

    #[test]
    fn config_builder_pattern() {
        let config = OtelStructuredConcurrencyConfig::new()
            .with_global_sample_rate(0.5)
            .with_span_type_sample_rate(SpanType::Region, 1.0)
            .with_always_sample(SpanType::Task)
            .with_max_active_spans(5000)
            .with_debug_info();

        assert_eq!(config.global_sample_rate, 0.5);
        assert_eq!(config.span_type_rates[&SpanType::Region], 1.0);
        assert!(config.always_sample.contains(&SpanType::Task));
        assert_eq!(config.max_active_spans, 5000);
        assert!(config.include_debug_info);
    }

    #[test]
    fn span_type_names() {
        assert_eq!(SpanType::Region.default_name(), "region_lifecycle");
        assert_eq!(SpanType::Task.default_name(), "task_execution");
        assert_eq!(SpanType::Operation.default_name(), "operation");
        assert_eq!(SpanType::Cancel.default_name(), "cancellation_event");
    }

    #[test]
    fn entity_id_variants() {
        let region_id = RegionId::new_for_test(1, 1);
        let task_id = TaskId::new_for_test(2, 1);

        let region_entity = EntityId::Region(region_id);
        let task_entity = EntityId::Task(task_id);
        let op_entity = EntityId::Operation(3);
        let cancel_entity = EntityId::Cancel(4);

        assert_ne!(region_entity, task_entity);
        assert_ne!(op_entity, cancel_entity);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn span_storage_creation() {
        let config = OtelStructuredConcurrencyConfig::default();
        let storage = SpanStorage::new(config);

        let (
            created,
            materialized,
            dropped_overflow,
            dropped_sampling,
            context_propagations,
            lazy_materializations,
        ) = storage.stats();
        assert_eq!(created, 0);
        assert_eq!(materialized, 0);
        assert_eq!(dropped_overflow, 0);
        assert_eq!(dropped_sampling, 0);
        assert_eq!(context_propagations, 0);
        assert_eq!(lazy_materializations, 0);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn span_storage_tracks_context_and_lazy_materialization_separately() {
        let mut config = OtelStructuredConcurrencyConfig::new().with_global_sample_rate(1.0);
        // Materialize after the two operations recorded below (the default lazy
        // threshold is 5, which would never trip for this two-operation case).
        config.lazy_threshold = 2;
        let storage = SpanStorage::new(config);
        let tracer = opentelemetry::global::tracer("otel-structured-concurrency-test");
        let entity = EntityId::Operation(17);

        assert!(storage.create_pending_span(
            SpanType::Operation,
            entity,
            "op".to_string(),
            Time::from_nanos(5),
            Some(opentelemetry::Context::new()),
        ));
        storage.add_span_operation(entity);
        storage.add_span_operation(entity);
        assert!(storage.maybe_materialize_span(entity, &tracer));

        let (
            created,
            materialized,
            dropped_overflow,
            dropped_sampling,
            context_propagations,
            lazy_materializations,
        ) = storage.stats();
        assert_eq!(created, 1);
        assert_eq!(materialized, 1);
        assert_eq!(dropped_overflow, 0);
        assert_eq!(dropped_sampling, 0);
        assert_eq!(context_propagations, 1);
        assert_eq!(lazy_materializations, 1);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn ending_pending_span_is_not_counted_as_lazy_materialization() {
        let config = OtelStructuredConcurrencyConfig::new()
            .with_global_sample_rate(1.0)
            .with_max_active_spans(8);
        let storage = SpanStorage::new(config);
        let tracer = opentelemetry::global::tracer("otel-structured-concurrency-test");
        let entity = EntityId::Task(TaskId::new_for_test(9, 1));

        assert!(storage.create_pending_span(
            SpanType::Task,
            entity,
            "task".to_string(),
            Time::from_nanos(9),
            None,
        ));
        storage.end_span(entity, &tracer);

        let (_, materialized, _, _, _, lazy_materializations) = storage.stats();
        assert_eq!(materialized, 1);
        assert_eq!(lazy_materializations, 0);
    }
