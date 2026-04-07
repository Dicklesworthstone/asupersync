//! FABRIC-specific lab oracles for messaging invariants.
//!
//! These oracles are feature-gated behind `messaging-fabric` because they
//! reason about the semantic seams exposed by `src/messaging/fabric.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::{Oracle, OracleStats, OracleViolation};
use crate::messaging::fabric::CellId;
use crate::messaging::{DeliveryClass, Subject, SubjectPattern};
use crate::types::{RegionId, Time};

/// A committed publish did not reach every matching subscriber.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricPublishViolation {
    /// Stable publish identifier assigned by the oracle.
    pub publish_id: u64,
    /// Concrete subject committed to the packet plane.
    pub subject: Subject,
    /// Subscribers whose patterns matched at commit time but never observed the publish.
    pub missing_subscribers: Vec<u64>,
    /// Timestamp when the publish was committed.
    pub committed_at: Time,
}

impl fmt::Display for FabricPublishViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FABRIC publish {} on {} committed at {:?} missed {} subscriber(s): {:?}",
            self.publish_id,
            self.subject,
            self.committed_at,
            self.missing_subscribers.len(),
            self.missing_subscribers
        )
    }
}

impl std::error::Error for FabricPublishViolation {}

#[derive(Debug, Clone)]
struct FabricPublishRecord {
    subject: Subject,
    committed_at: Time,
    expected_subscribers: Vec<u64>,
}

/// Oracle for the invariant "committed publish appears in the subscriber set".
#[derive(Debug, Default)]
pub struct FabricPublishOracle {
    subscribers: BTreeMap<u64, SubjectPattern>,
    publishes: BTreeMap<u64, FabricPublishRecord>,
    deliveries: BTreeSet<(u64, u64)>,
    next_publish_id: u64,
}

impl FabricPublishOracle {
    /// Create a new publish oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a subscriber and the subject pattern it observes.
    pub fn register_subscription(&mut self, subscriber_id: u64, pattern: SubjectPattern) {
        self.subscribers.insert(subscriber_id, pattern);
    }

    /// Remove a subscriber from future publish expectations.
    pub fn remove_subscription(&mut self, subscriber_id: u64) {
        self.subscribers.remove(&subscriber_id);
    }

    /// Record a committed publish and return its stable oracle-local identifier.
    pub fn on_publish_committed(&mut self, subject: Subject, committed_at: Time) -> u64 {
        let publish_id = self.next_publish_id;
        self.next_publish_id = self.next_publish_id.saturating_add(1);

        let expected_subscribers = self
            .subscribers
            .iter()
            .filter_map(|(&subscriber_id, pattern)| {
                pattern.matches(&subject).then_some(subscriber_id)
            })
            .collect::<Vec<_>>();

        self.publishes.insert(
            publish_id,
            FabricPublishRecord {
                subject,
                committed_at,
                expected_subscribers,
            },
        );

        publish_id
    }

    /// Record that a subscriber observed the committed publish.
    pub fn on_subscriber_receive(&mut self, publish_id: u64, subscriber_id: u64) {
        self.deliveries.insert((publish_id, subscriber_id));
    }

    /// Verify that every committed publish reached every matching subscriber.
    pub fn check(&self) -> Result<(), FabricPublishViolation> {
        for (&publish_id, record) in &self.publishes {
            let missing_subscribers = record
                .expected_subscribers
                .iter()
                .copied()
                .filter(|subscriber_id| !self.deliveries.contains(&(publish_id, *subscriber_id)))
                .collect::<Vec<_>>();

            if !missing_subscribers.is_empty() {
                return Err(FabricPublishViolation {
                    publish_id,
                    subject: record.subject.clone(),
                    missing_subscribers,
                    committed_at: record.committed_at,
                });
            }
        }

        Ok(())
    }

    /// Reset the oracle.
    pub fn reset(&mut self) {
        self.subscribers.clear();
        self.publishes.clear();
        self.deliveries.clear();
    }

    /// Number of tracked subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Number of committed publishes.
    #[must_use]
    pub fn publish_count(&self) -> usize {
        self.publishes.len()
    }

    /// Number of observed publish deliveries.
    #[must_use]
    pub fn delivery_count(&self) -> usize {
        self.deliveries.len()
    }
}

impl Oracle for FabricPublishOracle {
    fn invariant_name(&self) -> &'static str {
        "fabric_publish"
    }

    fn violation(&self) -> Option<OracleViolation> {
        self.check().err().map(OracleViolation::FabricPublish)
    }

    fn stats(&self) -> OracleStats {
        OracleStats {
            entities_tracked: self.publish_count(),
            events_recorded: self.subscriber_count() + self.publish_count() + self.delivery_count(),
        }
    }
}

/// Obligation-backed reply remained unresolved when its owning region closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricReplyViolation {
    /// Region that closed with unresolved obligation-backed replies.
    pub region: RegionId,
    /// Request identifiers that remained unresolved at region close.
    pub unresolved_request_ids: Vec<String>,
    /// Timestamp of the close event.
    pub close_time: Time,
}

impl fmt::Display for FabricReplyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FABRIC reply invariant violated: region {:?} closed at {:?} with unresolved obligation-backed requests {:?}",
            self.region, self.close_time, self.unresolved_request_ids
        )
    }
}

impl std::error::Error for FabricReplyViolation {}

#[derive(Debug, Clone)]
struct FabricReplyRecord {
    region: RegionId,
    requested_at: Time,
    resolved_at: Option<Time>,
}

/// Oracle for the invariant "obligation-backed replies resolve before region close".
#[derive(Debug, Default)]
pub struct FabricReplyOracle {
    requests: BTreeMap<String, FabricReplyRecord>,
    closed_regions: BTreeMap<RegionId, Time>,
    violations: Vec<FabricReplyViolation>,
}

impl FabricReplyOracle {
    /// Create a new reply oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the start of a request/reply interaction.
    ///
    /// Only `ObligationBacked` or stronger delivery classes are tracked.
    pub fn on_request_started(
        &mut self,
        request_id: impl Into<String>,
        region: RegionId,
        delivery_class: DeliveryClass,
        requested_at: Time,
    ) {
        if delivery_class < DeliveryClass::ObligationBacked {
            return;
        }

        self.requests.insert(
            request_id.into(),
            FabricReplyRecord {
                region,
                requested_at,
                resolved_at: None,
            },
        );
    }

    /// Record successful reply resolution.
    pub fn on_reply_resolved(&mut self, request_id: impl AsRef<str>, resolved_at: Time) {
        if let Some(record) = self.requests.get_mut(request_id.as_ref()) {
            record.resolved_at = Some(resolved_at);
        }
    }

    /// Record region close and snapshot any unresolved obligation-backed requests.
    pub fn on_region_close(&mut self, region: RegionId, close_time: Time) {
        self.closed_regions.insert(region, close_time);

        let unresolved_request_ids = self
            .requests
            .iter()
            .filter_map(|(request_id, record)| {
                (record.region == region && record.resolved_at.is_none())
                    .then_some(request_id.clone())
            })
            .collect::<Vec<_>>();

        if !unresolved_request_ids.is_empty() {
            self.violations.push(FabricReplyViolation {
                region,
                unresolved_request_ids,
                close_time,
            });
        }
    }

    /// Verify the reply invariant.
    pub fn check(&self) -> Result<(), FabricReplyViolation> {
        if let Some(violation) = self.violations.first() {
            return Err(violation.clone());
        }
        Ok(())
    }

    /// Reset the oracle.
    pub fn reset(&mut self) {
        self.requests.clear();
        self.closed_regions.clear();
        self.violations.clear();
    }

    /// Number of tracked obligation-backed requests.
    #[must_use]
    pub fn request_count(&self) -> usize {
        self.requests.len()
    }

    /// Number of resolved requests.
    #[must_use]
    pub fn resolved_count(&self) -> usize {
        self.requests
            .values()
            .filter(|record| record.resolved_at.is_some())
            .count()
    }

    /// Number of regions observed closing.
    #[must_use]
    pub fn closed_region_count(&self) -> usize {
        self.closed_regions.len()
    }

    /// Oldest tracked request timestamp, if any.
    #[must_use]
    pub fn oldest_request_time(&self) -> Option<Time> {
        self.requests
            .values()
            .map(|record| record.requested_at)
            .min()
    }
}

impl Oracle for FabricReplyOracle {
    fn invariant_name(&self) -> &'static str {
        "fabric_reply"
    }

    fn violation(&self) -> Option<OracleViolation> {
        self.check().err().map(OracleViolation::FabricReply)
    }

    fn stats(&self) -> OracleStats {
        OracleStats {
            entities_tracked: self.request_count(),
            events_recorded: self.request_count()
                + self.resolved_count()
                + self.closed_region_count(),
        }
    }
}

/// Region closed while one or more FABRIC cells still buffered data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricQuiescenceViolation {
    /// Region that closed without all FABRIC cells draining.
    pub region: RegionId,
    /// Busy cells and their buffered depths at close time.
    pub busy_cells: Vec<(CellId, usize)>,
    /// Timestamp of the close event.
    pub close_time: Time,
}

impl fmt::Display for FabricQuiescenceViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FABRIC quiescence violated: region {:?} closed at {:?} with busy cells {:?}",
            self.region, self.close_time, self.busy_cells
        )
    }
}

impl std::error::Error for FabricQuiescenceViolation {}

#[derive(Debug, Clone)]
struct FabricCellObservation {
    region: RegionId,
    buffered_messages: usize,
    last_observed_at: Time,
}

/// Oracle for the invariant "all tracked FABRIC cells are quiescent on region close".
#[derive(Debug, Default)]
pub struct FabricQuiescenceOracle {
    cells: BTreeMap<CellId, FabricCellObservation>,
    closed_regions: BTreeMap<RegionId, Time>,
    observations: usize,
    violations: Vec<FabricQuiescenceViolation>,
}

impl FabricQuiescenceOracle {
    /// Create a new FABRIC quiescence oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe the buffered depth for a FABRIC cell owned by `region`.
    pub fn observe_cell(
        &mut self,
        region: RegionId,
        cell_id: CellId,
        buffered_messages: usize,
        observed_at: Time,
    ) {
        self.observations = self.observations.saturating_add(1);
        self.cells.insert(
            cell_id,
            FabricCellObservation {
                region,
                buffered_messages,
                last_observed_at: observed_at,
            },
        );
    }

    /// Record region close and snapshot any busy cells.
    pub fn on_region_close(&mut self, region: RegionId, close_time: Time) {
        self.closed_regions.insert(region, close_time);

        let busy_cells = self
            .cells
            .iter()
            .filter_map(|(&cell_id, observation)| {
                (observation.region == region && observation.buffered_messages > 0)
                    .then_some((cell_id, observation.buffered_messages))
            })
            .collect::<Vec<_>>();

        if !busy_cells.is_empty() {
            self.violations.push(FabricQuiescenceViolation {
                region,
                busy_cells,
                close_time,
            });
        }
    }

    /// Verify FABRIC quiescence.
    pub fn check(&self) -> Result<(), FabricQuiescenceViolation> {
        if let Some(violation) = self.violations.first() {
            return Err(violation.clone());
        }
        Ok(())
    }

    /// Reset the oracle.
    pub fn reset(&mut self) {
        self.cells.clear();
        self.closed_regions.clear();
        self.observations = 0;
        self.violations.clear();
    }

    /// Number of tracked cells.
    #[must_use]
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// Number of cell observations.
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.observations
    }

    /// Number of regions observed closing.
    #[must_use]
    pub fn closed_region_count(&self) -> usize {
        self.closed_regions.len()
    }

    /// Latest observation time for any tracked cell.
    #[must_use]
    pub fn last_observed_at(&self) -> Option<Time> {
        self.cells.values().map(|cell| cell.last_observed_at).max()
    }
}

impl Oracle for FabricQuiescenceOracle {
    fn invariant_name(&self) -> &'static str {
        "fabric_quiescence"
    }

    fn violation(&self) -> Option<OracleViolation> {
        self.check().err().map(OracleViolation::FabricQuiescence)
    }

    fn stats(&self) -> OracleStats {
        OracleStats {
            entities_tracked: self.cell_count(),
            events_recorded: self.observation_count() + self.closed_region_count(),
        }
    }
}

/// A message exceeded the configured redelivery bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricRedeliveryViolation {
    /// Stable message identifier tracked by the oracle.
    pub message_id: String,
    /// Maximum permitted redeliveries.
    pub max_redeliveries: u32,
    /// Actual redelivery count observed.
    pub observed_redeliveries: u32,
    /// Timestamp of the latest redelivery attempt.
    pub last_redelivery_at: Time,
}

impl fmt::Display for FabricRedeliveryViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FABRIC redelivery bound exceeded for {}: observed {} redeliveries > {} at {:?}",
            self.message_id,
            self.observed_redeliveries,
            self.max_redeliveries,
            self.last_redelivery_at
        )
    }
}

impl std::error::Error for FabricRedeliveryViolation {}

#[derive(Debug, Clone)]
struct FabricRedeliveryRecord {
    max_redeliveries: u32,
    observed_redeliveries: u32,
    last_redelivery_at: Time,
    bound_explicit: bool,
}

/// Oracle for the invariant "redelivery remains bounded".
#[derive(Debug, Default)]
pub struct FabricRedeliveryOracle {
    messages: BTreeMap<String, FabricRedeliveryRecord>,
    redelivery_events: usize,
}

impl FabricRedeliveryOracle {
    /// Create a new redelivery oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin tracking a delivery with an explicit redelivery bound.
    ///
    /// Re-tracking an existing message preserves any redeliveries already
    /// observed so late or duplicate tracking cannot erase evidence. Once a
    /// message has an explicit bound, later calls may only tighten it.
    pub fn track_message(&mut self, message_id: impl Into<String>, max_redeliveries: u32) {
        use std::collections::btree_map::Entry;

        match self.messages.entry(message_id.into()) {
            Entry::Vacant(entry) => {
                entry.insert(FabricRedeliveryRecord {
                    max_redeliveries,
                    observed_redeliveries: 0,
                    last_redelivery_at: Time::ZERO,
                    bound_explicit: true,
                });
            }
            Entry::Occupied(mut entry) => {
                let record = entry.get_mut();
                if record.bound_explicit {
                    record.max_redeliveries = record.max_redeliveries.min(max_redeliveries);
                } else {
                    record.max_redeliveries = max_redeliveries;
                    record.bound_explicit = true;
                }
            }
        }
    }

    /// Record one redelivery attempt for the tracked message.
    pub fn on_redelivery(&mut self, message_id: impl AsRef<str>, attempt_time: Time) {
        self.redelivery_events = self.redelivery_events.saturating_add(1);
        let record = self
            .messages
            .entry(message_id.as_ref().to_owned())
            .or_insert(FabricRedeliveryRecord {
                max_redeliveries: 0,
                observed_redeliveries: 0,
                last_redelivery_at: attempt_time,
                bound_explicit: false,
            });
        record.observed_redeliveries = record.observed_redeliveries.saturating_add(1);
        record.last_redelivery_at = attempt_time;
    }

    /// Verify that no tracked message exceeded its redelivery bound.
    pub fn check(&self) -> Result<(), FabricRedeliveryViolation> {
        for (message_id, record) in &self.messages {
            if record.observed_redeliveries > record.max_redeliveries {
                return Err(FabricRedeliveryViolation {
                    message_id: message_id.clone(),
                    max_redeliveries: record.max_redeliveries,
                    observed_redeliveries: record.observed_redeliveries,
                    last_redelivery_at: record.last_redelivery_at,
                });
            }
        }

        Ok(())
    }

    /// Reset the oracle.
    pub fn reset(&mut self) {
        self.messages.clear();
        self.redelivery_events = 0;
    }

    /// Number of tracked messages.
    #[must_use]
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Number of redelivery events.
    #[must_use]
    pub fn redelivery_event_count(&self) -> usize {
        self.redelivery_events
    }
}

impl Oracle for FabricRedeliveryOracle {
    fn invariant_name(&self) -> &'static str {
        "fabric_redelivery"
    }

    fn violation(&self) -> Option<OracleViolation> {
        self.check().err().map(OracleViolation::FabricRedelivery)
    }

    fn stats(&self) -> OracleStats {
        OracleStats {
            entities_tracked: self.message_count(),
            events_recorded: self.message_count() + self.redelivery_event_count(),
        }
    }
}

#[cfg(test)]
mod tests {
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
        let recorder = EventRecorder { events };
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
}
