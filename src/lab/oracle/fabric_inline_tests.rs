    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::oracle::{EvidenceLedger, OracleSuite};
    use parking_lot::Mutex;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tracing::Subscriber;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry::LookupSpan;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedEvent {
        fields: BTreeMap<String, String>,
    }

    #[derive(Default)]
    struct EventFieldVisitor {
        fields: BTreeMap<String, String>,
    }

    impl Visit for EventFieldVisitor {
        fn record_bool(&mut self, field: &Field, value: bool) {
            self.fields
                .insert(field.name().to_owned(), value.to_string());
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.fields
                .insert(field.name().to_owned(), value.to_string());
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .insert(field.name().to_owned(), value.to_owned());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    #[derive(Default)]
    struct EventRecorder {
        events: Arc<Mutex<Vec<RecordedEvent>>>,
    }

    impl<S> Layer<S> for EventRecorder
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = EventFieldVisitor::default();
            event.record(&mut visitor);
            self.events.lock().push(RecordedEvent {
                fields: visitor.fields,
            });
        }
    }

    fn region(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    fn cell(pattern: &str, membership_epoch: u64, generation: u64) -> CellId {
        CellId::for_partition(
            crate::messaging::fabric::CellEpoch::new(membership_epoch, generation),
            &SubjectPattern::new(pattern),
        )
    }

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn publish_oracle_passes_when_all_matching_subscribers_receive_publish() {
        init_test("publish_oracle_passes_when_all_matching_subscribers_receive_publish");

        let mut oracle = FabricPublishOracle::new();
        oracle.register_subscription(1, SubjectPattern::new("orders.>"));
        oracle.register_subscription(2, SubjectPattern::new("orders.created"));
        oracle.register_subscription(3, SubjectPattern::new("billing.>"));

        let publish_id = oracle.on_publish_committed(Subject::new("orders.created"), t(10));
        oracle.on_subscriber_receive(publish_id, 1);
        oracle.on_subscriber_receive(publish_id, 2);

        assert!(oracle.check().is_ok());
        assert_eq!(oracle.publish_count(), 1);
        assert_eq!(oracle.delivery_count(), 2);
    }

    #[test]
    fn publish_oracle_detects_missing_matching_delivery() {
        init_test("publish_oracle_detects_missing_matching_delivery");

        let mut oracle = FabricPublishOracle::new();
        oracle.register_subscription(1, SubjectPattern::new("orders.>"));
        oracle.register_subscription(2, SubjectPattern::new("orders.created"));

        let publish_id = oracle.on_publish_committed(Subject::new("orders.created"), t(10));
        oracle.on_subscriber_receive(publish_id, 1);

        let violation = oracle.check().expect_err("missing subscriber must violate");
        assert_eq!(violation.publish_id, publish_id);
        assert_eq!(violation.missing_subscribers, vec![2]);
    }

    #[test]
    fn reply_oracle_passes_when_obligation_backed_request_resolves_before_close() {
        init_test("reply_oracle_passes_when_obligation_backed_request_resolves_before_close");

        let mut oracle = FabricReplyOracle::new();
        let region = region(7);
        oracle.on_request_started("req-1", region, DeliveryClass::ObligationBacked, t(10));
        oracle.on_reply_resolved("req-1", t(20));
        oracle.on_region_close(region, t(30));

        assert!(oracle.check().is_ok());
        assert_eq!(oracle.request_count(), 1);
        assert_eq!(oracle.resolved_count(), 1);
        assert_eq!(oracle.oldest_request_time(), Some(t(10)));
    }

    #[test]
    fn reply_oracle_ignores_ephemeral_requests() {
        init_test("reply_oracle_ignores_ephemeral_requests");

        let mut oracle = FabricReplyOracle::new();
        let region = region(9);
        oracle.on_request_started(
            "req-ephemeral",
            region,
            DeliveryClass::EphemeralInteractive,
            t(10),
        );
        oracle.on_region_close(region, t(20));

        assert!(oracle.check().is_ok());
        assert_eq!(oracle.request_count(), 0);
    }

    #[test]
    fn reply_oracle_detects_unresolved_request_on_close() {
        init_test("reply_oracle_detects_unresolved_request_on_close");

        let mut oracle = FabricReplyOracle::new();
        let region = region(3);
        oracle.on_request_started("req-1", region, DeliveryClass::ObligationBacked, t(10));
        oracle.on_region_close(region, t(20));

        let violation = oracle.check().expect_err("unresolved reply must violate");
        assert_eq!(violation.region, region);
        assert_eq!(violation.unresolved_request_ids, vec!["req-1".to_owned()]);
    }

    #[test]
    fn quiescence_oracle_passes_when_cells_are_drained_on_close() {
        init_test("quiescence_oracle_passes_when_cells_are_drained_on_close");

        let mut oracle = FabricQuiescenceOracle::new();
        let region = region(5);
        let cell = cell("orders.created", 1, 0);
        oracle.observe_cell(region, cell, 2, t(10));
        oracle.observe_cell(region, cell, 0, t(20));
        oracle.on_region_close(region, t(30));

        assert!(oracle.check().is_ok());
        assert_eq!(oracle.cell_count(), 1);
        assert_eq!(oracle.last_observed_at(), Some(t(20)));
    }

    #[test]
    fn quiescence_oracle_detects_busy_cells_on_close() {
        init_test("quiescence_oracle_detects_busy_cells_on_close");

        let mut oracle = FabricQuiescenceOracle::new();
        let region = region(6);
        let cell = cell("orders.created", 1, 0);
        oracle.observe_cell(region, cell, 1, t(10));
        oracle.on_region_close(region, t(20));

        let violation = oracle.check().expect_err("busy cell must violate");
        assert_eq!(violation.region, region);
        assert_eq!(violation.busy_cells, vec![(cell, 1)]);
    }

    #[test]
    fn redelivery_oracle_passes_within_bound() {
        init_test("redelivery_oracle_passes_within_bound");

        let mut oracle = FabricRedeliveryOracle::new();
        oracle.track_message("msg-1", 2);
        oracle.on_redelivery("msg-1", t(10));
        oracle.on_redelivery("msg-1", t(20));

        assert!(oracle.check().is_ok());
        assert_eq!(oracle.message_count(), 1);
        assert_eq!(oracle.redelivery_event_count(), 2);
    }

    #[test]
    fn redelivery_oracle_detects_exceeded_bound() {
        init_test("redelivery_oracle_detects_exceeded_bound");

        let mut oracle = FabricRedeliveryOracle::new();
        oracle.track_message("msg-1", 1);
        oracle.on_redelivery("msg-1", t(10));
        oracle.on_redelivery("msg-1", t(20));

        let violation = oracle.check().expect_err("bound overflow must violate");
        assert_eq!(violation.message_id, "msg-1");
        assert_eq!(violation.max_redeliveries, 1);
        assert_eq!(violation.observed_redeliveries, 2);
    }

    #[test]
    fn redelivery_oracle_duplicate_tracking_does_not_erase_redelivery_history() {
        init_test("redelivery_oracle_duplicate_tracking_does_not_erase_redelivery_history");

        let mut oracle = FabricRedeliveryOracle::new();
        oracle.track_message("msg-1", 1);
        oracle.on_redelivery("msg-1", t(10));

        // Re-tracking the same message must not discard the prior redelivery.
        oracle.track_message("msg-1", 4);
        oracle.on_redelivery("msg-1", t(20));

        let violation = oracle
            .check()
            .expect_err("duplicate tracking must not relax the original bound");
        assert_eq!(violation.message_id, "msg-1");
        assert_eq!(violation.max_redeliveries, 1);
        assert_eq!(violation.observed_redeliveries, 2);
        assert_eq!(violation.last_redelivery_at, t(20));
    }

    #[test]
    fn redelivery_oracle_late_tracking_preserves_prior_redelivery_observations() {
        init_test("redelivery_oracle_late_tracking_preserves_prior_redelivery_observations");

        let mut oracle = FabricRedeliveryOracle::new();

        // Redelivery can be observed before the bound is later attached.
        oracle.on_redelivery("msg-1", t(10));
        oracle.track_message("msg-1", 2);
        oracle.on_redelivery("msg-1", t(20));
        oracle.on_redelivery("msg-1", t(30));

        let violation = oracle
            .check()
            .expect_err("late tracking must retain already-observed redeliveries");
        assert_eq!(violation.message_id, "msg-1");
        assert_eq!(violation.max_redeliveries, 2);
        assert_eq!(violation.observed_redeliveries, 3);
        assert_eq!(violation.last_redelivery_at, t(30));
    }

    #[test]
    fn fabric_oracles_are_reported_and_emit_evidence() {
        init_test("fabric_oracles_are_reported_and_emit_evidence");

        let mut suite = OracleSuite::new();
        suite
            .fabric_publish
            .register_subscription(1, SubjectPattern::new("orders.>"));
        suite
            .fabric_publish
            .on_publish_committed(Subject::new("orders.created"), t(10));

        let events = Arc::new(Mutex::new(Vec::new()));
        let recorder = EventRecorder {
            events: events.clone(),
        };
        let subscriber = tracing_subscriber::registry().with(recorder);

        let report = tracing::subscriber::with_default(subscriber, || suite.report(t(20)));
        let entry = report
            .entry("fabric_publish")
            .expect("fabric publish entry should exist");
        assert!(
            !entry.passed,
            "undelivered publish should fail report entry"
        );

        let ledger = EvidenceLedger::from_report(&report);
        let evidence_entry = ledger
            .entries
            .iter()
            .find(|entry| entry.invariant == "fabric_publish")
            .expect("fabric publish evidence entry should exist");
        assert!(!evidence_entry.passed);

        // Tracing event assertions require the tracing-integration feature.
        // Without it, crate::tracing_compat::info! is a no-op.
        #[cfg(feature = "tracing-integration")]
        {
            let events = events.lock();
            let fabric_publish_event = events.iter().find(|event| {
                event.fields.get("event").map(String::as_str) == Some("oracle_check")
                    && event.fields.get("invariant").map(String::as_str) == Some("fabric_publish")
            });
            let fabric_publish_event =
                fabric_publish_event.expect("fabric publish oracle_check should be emitted");

            assert_eq!(
                fabric_publish_event
                    .fields
                    .get("passed")
                    .map(String::as_str),
                Some("false")
            );
            assert!(
                fabric_publish_event
                    .fields
                    .get("details")
                    .is_some_and(|details| details.contains("missed 1 subscriber")),
                "fabric publish oracle_check should preserve violation details",
            );
        }
        // Suppress unused-variable warning when tracing-integration is off.
        #[cfg(not(feature = "tracing-integration"))]
        let _ = events;
    }
