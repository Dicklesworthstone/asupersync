    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::distributed::context::{RegionTag, SymbolTraceContext};
    use crate::trace::distributed::id::{DistTraceId, SymbolSpanId};
    use crate::trace::distributed::span::SymbolSpan;
    use crate::types::symbol::SymbolId;
    use crate::util::DetRng;

    #[test]
    fn collector_records_spans() {
        let collector = SymbolTraceCollector::new(RegionTag::new("test"));
        let mut rng = DetRng::new(42);
        let trace_id = DistTraceId::new_for_test(1);
        let ctx = SymbolTraceContext::new_for_encoding(
            trace_id,
            SymbolSpanId::NIL,
            RegionTag::new("us-east-1"),
            &mut rng,
        );
        let span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(1), Time::from_millis(0));
        collector.record_span(&span, Time::from_millis(0));

        let record = collector.get_trace(trace_id).expect("trace should exist");
        assert_eq!(record.spans.len(), 1);
        assert_eq!(record.regions.len(), 1);
    }

    #[test]
    fn collector_detects_completion() {
        let collector = SymbolTraceCollector::new(RegionTag::new("test"));
        let mut rng = DetRng::new(7);
        let trace_id = DistTraceId::new_for_test(2);
        let ctx = SymbolTraceContext::new_for_encoding(
            trace_id,
            SymbolSpanId::NIL,
            RegionTag::new("sender"),
            &mut rng,
        );
        let mut decode_span =
            SymbolSpan::new_decode(ctx, ObjectId::new_for_test(2), 4, Time::from_millis(100));
        decode_span.complete_ok(Time::from_millis(120));
        collector.record_span(&decode_span, Time::from_millis(120));

        let record = collector.get_trace(trace_id).expect("trace should exist");
        assert!(record.is_complete);
        assert_eq!(collector.complete_traces(), vec![trace_id]);
    }

    #[test]
    fn trace_summary_calculations() {
        let collector = SymbolTraceCollector::new(RegionTag::new("test"));
        let mut rng = DetRng::new(42);
        let trace_id = DistTraceId::new_for_test(3);
        let object_id = ObjectId::new_for_test(3);
        let ctx = SymbolTraceContext::new_for_encoding(
            trace_id,
            SymbolSpanId::NIL,
            RegionTag::new("sender"),
            &mut rng,
        );

        let mut encode_span = SymbolSpan::new_encode(ctx.clone(), object_id, Time::from_millis(0));
        encode_span.set_symbol_count(10);
        encode_span.complete_ok(Time::from_millis(100));
        collector.record_span(&encode_span, Time::from_millis(100));

        for i in 0..10 {
            let mut tx_span = SymbolSpan::new_transmit(
                ctx.child(&mut rng),
                SymbolId::new_for_test(3, 0, i),
                Time::from_millis(100 + u64::from(i) * 10),
            );
            tx_span.complete_ok(Time::from_millis(150 + u64::from(i) * 10));
            collector.record_span(&tx_span, Time::from_millis(150 + u64::from(i) * 10));
        }

        let mut decode_span =
            SymbolSpan::new_decode(ctx.child(&mut rng), object_id, 10, Time::from_millis(300));
        decode_span.complete_ok(Time::from_millis(400));
        collector.record_span(&decode_span, Time::from_millis(400));

        let summary = collector
            .get_summary(trace_id)
            .expect("summary should exist");
        assert_eq!(summary.symbols_encoded, 10);
        assert_eq!(summary.symbols_transmitted, 10);
        assert!(summary.success);
        assert!(summary.end_to_end_latency.is_some());
    }

    // Pure data-type tests (wave 18 – CyanBarn)

    #[test]
    fn trace_record_debug_clone() {
        let collector = SymbolTraceCollector::new(RegionTag::new("test"));
        let mut rng = DetRng::new(42);
        let trace_id = DistTraceId::new_for_test(10);
        let ctx = SymbolTraceContext::new_for_encoding(
            trace_id,
            SymbolSpanId::NIL,
            RegionTag::new("region-a"),
            &mut rng,
        );
        let span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(1), Time::from_millis(0));
        collector.record_span(&span, Time::from_millis(0));

        let record = collector.get_trace(trace_id).unwrap();
        let record2 = record;
        assert_eq!(record2.trace_id, trace_id);
        assert!(!record2.is_complete);
        insta::assert_debug_snapshot!(record2);
    }

    #[test]
    fn trace_summary_debug_clone() {
        let collector = SymbolTraceCollector::new(RegionTag::new("test"));
        let mut rng = DetRng::new(42);
        let trace_id = DistTraceId::new_for_test(20);
        let ctx = SymbolTraceContext::new_for_encoding(
            trace_id,
            SymbolSpanId::NIL,
            RegionTag::new("r"),
            &mut rng,
        );
        let mut span = SymbolSpan::new_encode(ctx, ObjectId::new_for_test(1), Time::from_millis(0));
        span.set_symbol_count(5);
        span.complete_ok(Time::from_millis(100));
        collector.record_span(&span, Time::from_millis(100));

        let summary = collector.get_summary(trace_id).unwrap();
        let summary2 = summary;
        assert_eq!(summary2.symbols_encoded, 5);
        insta::assert_debug_snapshot!(summary2);
    }

    #[test]
    fn collector_builder_methods() {
        let collector = SymbolTraceCollector::new(RegionTag::new("us-west"))
            .with_max_traces(100)
            .with_max_age(Duration::from_secs(120))
            .with_clock_skew_tolerance(Duration::from_millis(50));

        assert_eq!(collector.local_region(), &RegionTag::new("us-west"));
        assert_eq!(collector.clock_skew_tolerance(), Duration::from_millis(50));
    }

    #[test]
    fn collector_get_nonexistent_trace() {
        let collector = SymbolTraceCollector::new(RegionTag::new("test"));
        assert!(
            collector
                .get_trace(DistTraceId::new_for_test(999))
                .is_none()
        );
        assert!(
            collector
                .get_summary(DistTraceId::new_for_test(999))
                .is_none()
        );
    }

    /// br-asupersync-q6vujm — accessors that walk the trace map must
    /// yield a deterministic order regardless of insertion order.
    /// `BTreeMap` orders by key (DistTraceId, which derives `Ord`) so
    /// inserting the same set in different orders observes the same
    /// iteration. The previous `HashMap` would have observed the
    /// random-seeded hash order, breaking byte-stable replay.
    #[test]
    fn deterministic_iteration_order_under_insertion_permutation() {
        let make = |ids: &[u64]| {
            let collector = SymbolTraceCollector::new(RegionTag::new("test"));
            for &id in ids {
                let mut rng = DetRng::new(id);
                let trace_id = DistTraceId::new_for_test(id);
                let ctx = SymbolTraceContext::new_for_encoding(
                    trace_id,
                    SymbolSpanId::NIL,
                    RegionTag::new("us-east-1"),
                    &mut rng,
                );
                let span =
                    SymbolSpan::new_encode(ctx, ObjectId::new_for_test(id), Time::from_millis(0));
                collector.record_span(&span, Time::from_millis(0));
            }
            // get_traces returns iteration of all keys.
            let traces = collector.traces.read();
            traces.keys().copied().collect::<Vec<_>>()
        };

        let order_a = make(&[5, 3, 1, 7, 9]);
        let order_b = make(&[9, 7, 5, 3, 1]);
        let order_c = make(&[1, 9, 3, 7, 5]);
        assert_eq!(order_a, order_b);
        assert_eq!(order_b, order_c);
    }
