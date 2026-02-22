//! Refinement firewall checks for core runtime temporal invariants.
//!
//! This checker is intentionally deterministic and first-violation oriented:
//! it returns the earliest violating event with a stable rule identifier so
//! failing traces can be triaged and minimized consistently.

use super::event::{TraceData, TraceEvent, TraceEventKind};
use crate::types::{ObligationId, RegionId, TaskId};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
struct TaskRecord {
    region: RegionId,
    completed: bool,
    cancel_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct RegionRecord {
    close_began: bool,
    close_completed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObligationRecord {
    task: TaskId,
    region: RegionId,
    resolved: bool,
}

/// First violation found by the refinement firewall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefinementViolation {
    /// Stable rule identifier for deterministic triage.
    pub rule_id: &'static str,
    /// Zero-based index of the violating event in the trace.
    pub event_index: usize,
    /// Sequence number of the violating event.
    pub event_seq: u64,
    /// Event kind where the violation was detected.
    pub event_kind: TraceEventKind,
    /// Human-readable violation detail.
    pub detail: String,
}

impl core::fmt::Display for RefinementViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} at event[{}] seq={} kind={}: {}",
            self.rule_id, self.event_index, self.event_seq, self.event_kind, self.detail
        )
    }
}

impl std::error::Error for RefinementViolation {}

/// Result of running refinement firewall checks over a trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefinementFirewallReport {
    /// Number of events evaluated before completion.
    pub checked_events: usize,
    /// First detected violation (if any).
    pub first_violation: Option<RefinementViolation>,
}

impl RefinementFirewallReport {
    /// Returns true when no violation was found.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.first_violation.is_none()
    }
}

/// Check core refinement invariants and return first violation information.
#[must_use]
pub fn check_refinement_firewall(events: &[TraceEvent]) -> RefinementFirewallReport {
    match first_refinement_violation(events) {
        Some(v) => RefinementFirewallReport {
            checked_events: v.event_index + 1,
            first_violation: Some(v),
        },
        None => RefinementFirewallReport {
            checked_events: events.len(),
            first_violation: None,
        },
    }
}

/// Validate refinement invariants and return the first violation as an error.
pub fn verify_refinement_firewall(events: &[TraceEvent]) -> Result<(), RefinementViolation> {
    first_refinement_violation(events).map_or(Ok(()), Err)
}

/// Return the first violation encountered while scanning the trace.
#[must_use]
pub fn first_refinement_violation(events: &[TraceEvent]) -> Option<RefinementViolation> {
    let mut state = FirewallState::default();
    for (idx, event) in events.iter().enumerate() {
        if let Some(v) = state.observe(idx, event) {
            return Some(v);
        }
    }
    None
}

/// Minimal deterministic counterexample prefix: all events up to first violation.
#[must_use]
pub fn first_counterexample_prefix(events: &[TraceEvent]) -> Option<Vec<TraceEvent>> {
    let violation = first_refinement_violation(events)?;
    Some(events[..=violation.event_index].to_vec())
}

#[derive(Debug, Default)]
struct FirewallState {
    tasks: BTreeMap<TaskId, TaskRecord>,
    regions: BTreeMap<RegionId, RegionRecord>,
    obligations: BTreeMap<ObligationId, ObligationRecord>,
    live_tasks_by_region: BTreeMap<RegionId, BTreeSet<TaskId>>,
    reserved_obligations_by_region: BTreeMap<RegionId, BTreeSet<ObligationId>>,
}

impl FirewallState {
    fn observe(&mut self, index: usize, event: &TraceEvent) -> Option<RefinementViolation> {
        match event.kind {
            TraceEventKind::Spawn => self.on_spawn(index, event),
            TraceEventKind::Complete => self.on_complete(index, event),
            TraceEventKind::CancelRequest => self.on_cancel_request(index, event),
            TraceEventKind::CancelAck => self.on_cancel_ack(index, event),
            TraceEventKind::RegionCreated => self.on_region_created(index, event),
            TraceEventKind::RegionCloseBegin => self.on_region_close_begin(index, event),
            TraceEventKind::RegionCloseComplete => self.on_region_close_complete(index, event),
            TraceEventKind::ObligationReserve => self.on_obligation_reserve(index, event),
            TraceEventKind::ObligationCommit => self.on_obligation_commit(index, event),
            TraceEventKind::ObligationAbort => self.on_obligation_abort(index, event),
            TraceEventKind::ObligationLeak => Some(violation(
                "RFW-OBL-004",
                index,
                event,
                "obligation leak event emitted".to_string(),
            )),
            _ => None,
        }
    }

    fn on_spawn(&mut self, index: usize, event: &TraceEvent) -> Option<RefinementViolation> {
        let (task, region) = match expect_task_data("RFW-SCHEMA-001", index, event) {
            Ok(v) => v,
            Err(v) => return Some(v),
        };

        if self.tasks.contains_key(&task) {
            return Some(violation(
                "RFW-SPAWN-001",
                index,
                event,
                format!("task {task} spawned more than once"),
            ));
        }

        let region_record = self.regions.entry(region).or_default();
        if region_record.close_completed {
            return Some(violation(
                "RFW-SPAWN-002",
                index,
                event,
                format!("task {task} spawned in already-closed region {region}"),
            ));
        }

        self.tasks.insert(
            task,
            TaskRecord {
                region,
                completed: false,
                cancel_requested: false,
            },
        );
        self.live_tasks_by_region
            .entry(region)
            .or_default()
            .insert(task);
        None
    }

    fn on_complete(&mut self, index: usize, event: &TraceEvent) -> Option<RefinementViolation> {
        let (task, region) = match expect_task_data("RFW-SCHEMA-002", index, event) {
            Ok(v) => v,
            Err(v) => return Some(v),
        };
        let Some(task_record) = self.tasks.get_mut(&task) else {
            return Some(violation(
                "RFW-TASK-001",
                index,
                event,
                format!("task {task} completed before spawn"),
            ));
        };

        if task_record.region != region {
            return Some(violation(
                "RFW-TASK-002",
                index,
                event,
                format!(
                    "task {task} completed in region {region}, expected {}",
                    task_record.region
                ),
            ));
        }

        if task_record.completed {
            return Some(violation(
                "RFW-TASK-003",
                index,
                event,
                format!("task {task} completed more than once"),
            ));
        }

        task_record.completed = true;
        if let Some(live) = self.live_tasks_by_region.get_mut(&region) {
            live.remove(&task);
        }
        None
    }

    fn on_cancel_request(
        &mut self,
        index: usize,
        event: &TraceEvent,
    ) -> Option<RefinementViolation> {
        let (task, region) = match expect_cancel_data("RFW-SCHEMA-003", index, event) {
            Ok(v) => v,
            Err(v) => return Some(v),
        };
        let Some(task_record) = self.tasks.get_mut(&task) else {
            return Some(violation(
                "RFW-CANCEL-001",
                index,
                event,
                format!("cancel requested for unknown task {task}"),
            ));
        };

        if task_record.region != region {
            return Some(violation(
                "RFW-CANCEL-002",
                index,
                event,
                format!(
                    "cancel request for task {task} used region {region}, expected {}",
                    task_record.region
                ),
            ));
        }

        if task_record.completed {
            return Some(violation(
                "RFW-CANCEL-003",
                index,
                event,
                format!("cancel requested for already-completed task {task}"),
            ));
        }

        task_record.cancel_requested = true;
        None
    }

    fn on_cancel_ack(&self, index: usize, event: &TraceEvent) -> Option<RefinementViolation> {
        let (task, region) = match expect_cancel_data("RFW-SCHEMA-004", index, event) {
            Ok(v) => v,
            Err(v) => return Some(v),
        };
        let Some(task_record) = self.tasks.get(&task) else {
            return Some(violation(
                "RFW-CANCEL-004",
                index,
                event,
                format!("cancel ack for unknown task {task}"),
            ));
        };

        if task_record.region != region {
            return Some(violation(
                "RFW-CANCEL-005",
                index,
                event,
                format!(
                    "cancel ack for task {task} used region {region}, expected {}",
                    task_record.region
                ),
            ));
        }

        if !task_record.cancel_requested {
            return Some(violation(
                "RFW-CANCEL-006",
                index,
                event,
                format!("cancel ack observed before cancel request for task {task}"),
            ));
        }

        None
    }

    fn on_region_created(
        &mut self,
        index: usize,
        event: &TraceEvent,
    ) -> Option<RefinementViolation> {
        let region = match expect_region_data("RFW-SCHEMA-005", index, event) {
            Ok(v) => v,
            Err(v) => return Some(v),
        };
        let entry = self.regions.entry(region).or_default();

        if entry.close_began || entry.close_completed {
            return Some(violation(
                "RFW-REGION-001",
                index,
                event,
                format!("region {region} created after close lifecycle already started"),
            ));
        }

        None
    }

    fn on_region_close_begin(
        &mut self,
        index: usize,
        event: &TraceEvent,
    ) -> Option<RefinementViolation> {
        let region = match expect_region_data("RFW-SCHEMA-006", index, event) {
            Ok(v) => v,
            Err(v) => return Some(v),
        };
        let entry = self.regions.entry(region).or_default();
        if entry.close_completed {
            return Some(violation(
                "RFW-REGION-002",
                index,
                event,
                format!("region {region} close-begin observed after close-complete"),
            ));
        }
        if entry.close_began {
            return Some(violation(
                "RFW-REGION-003",
                index,
                event,
                format!("region {region} close-begin observed more than once"),
            ));
        }
        entry.close_began = true;
        None
    }

    fn on_region_close_complete(
        &mut self,
        index: usize,
        event: &TraceEvent,
    ) -> Option<RefinementViolation> {
        let region = match expect_region_data("RFW-SCHEMA-007", index, event) {
            Ok(v) => v,
            Err(v) => return Some(v),
        };
        let entry = self.regions.entry(region).or_default();
        if !entry.close_began {
            return Some(violation(
                "RFW-REGION-004",
                index,
                event,
                format!("region {region} close-complete observed before close-begin"),
            ));
        }
        if entry.close_completed {
            return Some(violation(
                "RFW-REGION-005",
                index,
                event,
                format!("region {region} close-complete observed more than once"),
            ));
        }

        if let Some(live) = self.live_tasks_by_region.get(&region) {
            if !live.is_empty() {
                return Some(violation(
                    "RFW-QUIESCE-001",
                    index,
                    event,
                    format!(
                        "region {region} close-complete with {} live task(s)",
                        live.len()
                    ),
                ));
            }
        }

        if let Some(reserved) = self.reserved_obligations_by_region.get(&region) {
            if !reserved.is_empty() {
                return Some(violation(
                    "RFW-OBL-001",
                    index,
                    event,
                    format!(
                        "region {region} close-complete with {} unresolved obligation(s)",
                        reserved.len()
                    ),
                ));
            }
        }

        entry.close_completed = true;
        None
    }

    fn on_obligation_reserve(
        &mut self,
        index: usize,
        event: &TraceEvent,
    ) -> Option<RefinementViolation> {
        let (obligation, task, region) =
            match expect_obligation_data("RFW-SCHEMA-008", index, event) {
                Ok(v) => v,
                Err(v) => return Some(v),
            };

        if self.obligations.contains_key(&obligation) {
            return Some(violation(
                "RFW-OBL-002",
                index,
                event,
                format!("obligation {obligation} reserved more than once"),
            ));
        }

        let Some(task_record) = self.tasks.get(&task) else {
            return Some(violation(
                "RFW-OBL-003",
                index,
                event,
                format!("obligation {obligation} reserved by unknown task {task}"),
            ));
        };

        if task_record.region != region {
            return Some(violation(
                "RFW-OBL-005",
                index,
                event,
                format!(
                    "obligation {obligation} reserved in region {region}, expected {} for task {task}",
                    task_record.region
                ),
            ));
        }

        if task_record.completed {
            return Some(violation(
                "RFW-OBL-006",
                index,
                event,
                format!("obligation {obligation} reserved by already-completed task {task}"),
            ));
        }

        self.obligations.insert(
            obligation,
            ObligationRecord {
                task,
                region,
                resolved: false,
            },
        );
        self.reserved_obligations_by_region
            .entry(region)
            .or_default()
            .insert(obligation);
        None
    }

    fn on_obligation_commit(
        &mut self,
        index: usize,
        event: &TraceEvent,
    ) -> Option<RefinementViolation> {
        self.resolve_obligation(index, event, "RFW-SCHEMA-009", "RFW-OBL-007")
    }

    fn on_obligation_abort(
        &mut self,
        index: usize,
        event: &TraceEvent,
    ) -> Option<RefinementViolation> {
        self.resolve_obligation(index, event, "RFW-SCHEMA-010", "RFW-OBL-008")
    }

    fn resolve_obligation(
        &mut self,
        index: usize,
        event: &TraceEvent,
        schema_rule_id: &'static str,
        missing_rule_id: &'static str,
    ) -> Option<RefinementViolation> {
        let (obligation, task, region) = match expect_obligation_data(schema_rule_id, index, event)
        {
            Ok(v) => v,
            Err(v) => return Some(v),
        };

        let Some(record) = self.obligations.get_mut(&obligation) else {
            return Some(violation(
                missing_rule_id,
                index,
                event,
                format!("obligation {obligation} resolved before reserve"),
            ));
        };

        if record.task != task || record.region != region {
            return Some(violation(
                "RFW-OBL-009",
                index,
                event,
                format!(
                    "obligation {obligation} resolved by task {task} in region {region}, expected task {} in region {}",
                    record.task, record.region
                ),
            ));
        }

        if record.resolved {
            return Some(violation(
                "RFW-OBL-010",
                index,
                event,
                format!("obligation {obligation} resolved more than once"),
            ));
        }

        record.resolved = true;
        if let Some(pending) = self.reserved_obligations_by_region.get_mut(&region) {
            pending.remove(&obligation);
        }

        None
    }
}

fn expect_task_data(
    schema_rule_id: &'static str,
    index: usize,
    event: &TraceEvent,
) -> Result<(TaskId, RegionId), RefinementViolation> {
    match event.data {
        TraceData::Task { task, region } => Ok((task, region)),
        _ => Err(violation(
            schema_rule_id,
            index,
            event,
            "expected TraceData::Task".to_string(),
        )),
    }
}

fn expect_cancel_data(
    schema_rule_id: &'static str,
    index: usize,
    event: &TraceEvent,
) -> Result<(TaskId, RegionId), RefinementViolation> {
    match event.data {
        TraceData::Cancel { task, region, .. } => Ok((task, region)),
        _ => Err(violation(
            schema_rule_id,
            index,
            event,
            "expected TraceData::Cancel".to_string(),
        )),
    }
}

fn expect_region_data(
    schema_rule_id: &'static str,
    index: usize,
    event: &TraceEvent,
) -> Result<RegionId, RefinementViolation> {
    match event.data {
        TraceData::Region { region, .. } => Ok(region),
        _ => Err(violation(
            schema_rule_id,
            index,
            event,
            "expected TraceData::Region".to_string(),
        )),
    }
}

fn expect_obligation_data(
    schema_rule_id: &'static str,
    index: usize,
    event: &TraceEvent,
) -> Result<(ObligationId, TaskId, RegionId), RefinementViolation> {
    match event.data {
        TraceData::Obligation {
            obligation,
            task,
            region,
            ..
        } => Ok((obligation, task, region)),
        _ => Err(violation(
            schema_rule_id,
            index,
            event,
            "expected TraceData::Obligation".to_string(),
        )),
    }
}

fn violation(
    rule_id: &'static str,
    event_index: usize,
    event: &TraceEvent,
    detail: String,
) -> RefinementViolation {
    RefinementViolation {
        rule_id,
        event_index,
        event_seq: event.seq,
        event_kind: event.kind,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{ObligationAbortReason, ObligationKind};
    use crate::types::{CancelReason, Time};

    fn rid(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    fn tid(n: u32) -> TaskId {
        TaskId::new_for_test(n, 0)
    }

    fn oid(n: u32) -> ObligationId {
        ObligationId::new_for_test(n, 0)
    }

    #[test]
    fn accepts_valid_core_lifecycle() {
        let events = vec![
            TraceEvent::region_created(1, Time::ZERO, rid(1), None),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::cancel_request(3, Time::ZERO, tid(1), rid(1), CancelReason::shutdown()),
            TraceEvent::new(
                4,
                Time::ZERO,
                TraceEventKind::CancelAck,
                TraceData::Cancel {
                    task: tid(1),
                    region: rid(1),
                    reason: CancelReason::shutdown(),
                },
            ),
            TraceEvent::obligation_reserve(
                5,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::SendPermit,
            ),
            TraceEvent::obligation_commit(
                6,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::SendPermit,
                3,
            ),
            TraceEvent::complete(7, Time::ZERO, tid(1), rid(1)),
            TraceEvent::new(
                8,
                Time::ZERO,
                TraceEventKind::RegionCloseBegin,
                TraceData::Region {
                    region: rid(1),
                    parent: None,
                },
            ),
            TraceEvent::new(
                9,
                Time::ZERO,
                TraceEventKind::RegionCloseComplete,
                TraceData::Region {
                    region: rid(1),
                    parent: None,
                },
            ),
        ];

        let report = check_refinement_firewall(&events);
        assert!(report.is_ok(), "report={report:?}");
        assert_eq!(report.checked_events, events.len());
        assert!(first_counterexample_prefix(&events).is_none());
    }

    #[test]
    fn duplicate_spawn_is_rejected() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
        ];

        let v = first_refinement_violation(&events).expect("expected violation");
        assert_eq!(v.rule_id, "RFW-SPAWN-001");
        assert_eq!(v.event_index, 1);
    }

    #[test]
    fn cancel_ack_without_request_is_rejected() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::new(
                2,
                Time::ZERO,
                TraceEventKind::CancelAck,
                TraceData::Cancel {
                    task: tid(1),
                    region: rid(1),
                    reason: CancelReason::shutdown(),
                },
            ),
        ];

        let v = first_refinement_violation(&events).expect("expected violation");
        assert_eq!(v.rule_id, "RFW-CANCEL-006");
    }

    #[test]
    fn close_complete_requires_quiescence() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::new(
                2,
                Time::ZERO,
                TraceEventKind::RegionCloseBegin,
                TraceData::Region {
                    region: rid(1),
                    parent: None,
                },
            ),
            TraceEvent::new(
                3,
                Time::ZERO,
                TraceEventKind::RegionCloseComplete,
                TraceData::Region {
                    region: rid(1),
                    parent: None,
                },
            ),
        ];

        let v = first_refinement_violation(&events).expect("expected violation");
        assert_eq!(v.rule_id, "RFW-QUIESCE-001");
    }

    #[test]
    fn resolve_without_reserve_is_rejected() {
        let events = vec![TraceEvent::obligation_commit(
            1,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::SendPermit,
            1,
        )];

        let v = first_refinement_violation(&events).expect("expected violation");
        assert_eq!(v.rule_id, "RFW-OBL-007");
    }

    #[test]
    fn obligation_region_mismatch_is_rejected() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::obligation_reserve(
                2,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(2),
                ObligationKind::Ack,
            ),
        ];

        let v = first_refinement_violation(&events).expect("expected violation");
        assert_eq!(v.rule_id, "RFW-OBL-005");
    }

    #[test]
    fn obligation_leak_event_is_immediate_violation() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::obligation_leak(
                2,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::Ack,
                99,
            ),
        ];

        let v = first_refinement_violation(&events).expect("expected violation");
        assert_eq!(v.rule_id, "RFW-OBL-004");
    }

    #[test]
    fn counterexample_prefix_cuts_at_first_violation() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::obligation_abort(
                3,
                Time::ZERO,
                oid(1),
                tid(1),
                rid(1),
                ObligationKind::SendPermit,
                1,
                ObligationAbortReason::Cancel,
            ),
        ];

        let prefix = first_counterexample_prefix(&events).expect("expected prefix");
        assert_eq!(prefix.len(), 2);
        assert_eq!(prefix[1].seq, 2);
    }
}
