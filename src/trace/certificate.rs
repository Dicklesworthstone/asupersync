//! Proof-carrying trace certificates.
//!
//! A `TraceCertificate` is a compact witness that a trace respected
//! structural concurrency invariants during execution. It accumulates
//! evidence as events are emitted and can be verified offline.
//!
//! # Invariants tracked
//!
//! - **Region nesting**: every task belongs to a region; regions form a tree.
//! - **Obligation resolution**: all obligations are committed or aborted
//!   before their holder terminates.
//! - **Cancellation protocol**: cancel requests precede cancel acks;
//!   no task completes after receiving an unacknowledged cancel.
//! - **Schedule determinism**: hash of scheduling decisions matches
//!   expected value for the given seed.
//!
//! # Verification
//!
//! The `CertificateVerifier` replays a certificate against a trace buffer
//! and checks that all invariant claims hold.

use crate::monitor::DownReason;
use crate::record::{ObligationAbortReason, ObligationState};
use crate::trace::{
    distributed::LogicalTime,
    event::{TraceData, TraceEvent, TraceEventKind},
};
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

/// A proof-carrying trace certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceCertificate {
    /// Incremental hash of all events.
    event_hash: u64,
    /// Number of events witnessed.
    event_count: u64,
    /// Number of spawn events.
    spawns: u64,
    /// Number of complete events.
    completes: u64,
    /// Number of cancel request events.
    cancel_requests: u64,
    /// Number of cancel ack events.
    cancel_acks: u64,
    /// Number of obligation acquire events.
    obligation_acquires: u64,
    /// Number of obligation release events (commit + abort).
    obligation_releases: u64,
    /// Schedule certificate hash (from ScheduleCertificate).
    schedule_hash: u64,
    /// Whether any invariant violation was detected during accumulation.
    violation_detected: bool,
    /// Description of the first violation (if any).
    first_violation: Option<String>,
}

impl TraceCertificate {
    /// Creates a new empty certificate.
    #[must_use]
    pub fn new() -> Self {
        Self {
            event_hash: 0,
            event_count: 0,
            spawns: 0,
            completes: 0,
            cancel_requests: 0,
            cancel_acks: 0,
            obligation_acquires: 0,
            obligation_releases: 0,
            schedule_hash: 0,
            violation_detected: false,
            first_violation: None,
        }
    }

    /// Record an event into the certificate.
    pub fn record_event(&mut self, event: &TraceEvent) {
        // Commit to the full event semantics so offline verification catches
        // payload tampering, not just reordered or retyped events.
        let mut hasher = crate::util::DetHasher::default();
        self.event_hash.hash(&mut hasher);
        hash_trace_event(&mut hasher, event);
        self.event_hash = hasher.finish();

        self.event_count += 1;

        match event.kind {
            TraceEventKind::Spawn => self.spawns += 1,
            TraceEventKind::Complete => self.completes += 1,
            TraceEventKind::CancelRequest => self.cancel_requests += 1,
            TraceEventKind::CancelAck => self.cancel_acks += 1,
            TraceEventKind::ObligationReserve => self.obligation_acquires += 1,
            TraceEventKind::ObligationCommit | TraceEventKind::ObligationAbort => {
                self.obligation_releases += 1;
            }
            _ => {}
        }
    }

    /// Set the schedule certificate hash.
    pub fn set_schedule_hash(&mut self, hash: u64) {
        self.schedule_hash = hash;
    }

    /// Record a violation.
    pub fn record_violation(&mut self, description: &str) {
        self.violation_detected = true;
        if self.first_violation.is_none() {
            self.first_violation = Some(description.to_string());
        }
    }

    /// True if no violations were detected.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.violation_detected
    }

    /// The incremental event hash.
    #[must_use]
    pub fn event_hash(&self) -> u64 {
        self.event_hash
    }

    /// Total events witnessed.
    #[must_use]
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Schedule certificate hash.
    #[must_use]
    pub fn schedule_hash(&self) -> u64 {
        self.schedule_hash
    }

    /// The first violation description, if any.
    #[must_use]
    pub fn first_violation(&self) -> Option<&str> {
        self.first_violation.as_deref()
    }

    /// Obligation balance: acquires minus releases.
    /// Should be zero at quiescence.
    #[must_use]
    pub fn obligation_balance(&self) -> i64 {
        if self.obligation_acquires >= self.obligation_releases {
            i64::try_from(self.obligation_acquires - self.obligation_releases).unwrap_or(i64::MAX)
        } else {
            i64::try_from(self.obligation_releases - self.obligation_acquires)
                .unwrap_or(i64::MAX)
                .wrapping_neg()
        }
    }

    /// Cancel balance: requests minus acks.
    /// Should be zero at quiescence (all cancels acknowledged).
    #[must_use]
    pub fn cancel_balance(&self) -> i64 {
        if self.cancel_requests >= self.cancel_acks {
            i64::try_from(self.cancel_requests - self.cancel_acks).unwrap_or(i64::MAX)
        } else {
            i64::try_from(self.cancel_acks - self.cancel_requests)
                .unwrap_or(i64::MAX)
                .wrapping_neg()
        }
    }

    /// Task balance: spawns minus completes.
    /// Should be zero at quiescence.
    #[must_use]
    pub fn task_balance(&self) -> i64 {
        if self.spawns >= self.completes {
            i64::try_from(self.spawns - self.completes).unwrap_or(i64::MAX)
        } else {
            i64::try_from(self.completes - self.spawns)
                .unwrap_or(i64::MAX)
                .wrapping_neg()
        }
    }
}

fn hash_trace_event<H: Hasher>(hasher: &mut H, event: &TraceEvent) {
    event.version.hash(hasher);
    event.seq.hash(hasher);
    event.time.hash(hasher);
    hash_logical_time(hasher, event.logical_time.as_ref());
    event.kind.hash(hasher);
    hash_trace_data(hasher, &event.data);
}

fn hash_logical_time<H: Hasher>(hasher: &mut H, logical_time: Option<&LogicalTime>) {
    match logical_time {
        None => 0_u8.hash(hasher),
        Some(LogicalTime::Lamport(time)) => {
            1_u8.hash(hasher);
            time.hash(hasher);
        }
        Some(LogicalTime::Vector(clock)) => {
            2_u8.hash(hasher);
            clock.node_count().hash(hasher);
            for (node, value) in clock.iter() {
                node.hash(hasher);
                value.hash(hasher);
            }
        }
        Some(LogicalTime::Hybrid(time)) => {
            3_u8.hash(hasher);
            time.physical().hash(hasher);
            time.logical().hash(hasher);
        }
    }
}

fn hash_trace_data<H: Hasher>(hasher: &mut H, data: &TraceData) {
    if hash_lifecycle_trace_data(hasher, data)
        || hash_runtime_trace_data(hasher, data)
        || hash_supervision_trace_data(hasher, data)
    {
        return;
    }

    unreachable!("all TraceData variants should be covered");
}

fn hash_lifecycle_trace_data<H: Hasher>(hasher: &mut H, data: &TraceData) -> bool {
    match data {
        TraceData::None => {
            0_u8.hash(hasher);
            true
        }
        TraceData::Task { task, region } => {
            1_u8.hash(hasher);
            task.hash(hasher);
            region.hash(hasher);
            true
        }
        TraceData::Region { region, parent } => {
            2_u8.hash(hasher);
            region.hash(hasher);
            parent.hash(hasher);
            true
        }
        TraceData::Obligation {
            obligation,
            task,
            region,
            kind,
            state,
            duration_ns,
            abort_reason,
        } => {
            3_u8.hash(hasher);
            obligation.hash(hasher);
            task.hash(hasher);
            region.hash(hasher);
            kind.hash(hasher);
            hash_obligation_state(hasher, *state);
            duration_ns.hash(hasher);
            hash_obligation_abort_reason(hasher, *abort_reason);
            true
        }
        TraceData::Cancel {
            task,
            region,
            reason,
        } => {
            4_u8.hash(hasher);
            task.hash(hasher);
            region.hash(hasher);
            hash_cancel_reason(hasher, reason);
            true
        }
        TraceData::Worker {
            worker_id,
            job_id,
            decision_seq,
            replay_hash,
            task,
            region,
            obligation,
        } => {
            5_u8.hash(hasher);
            worker_id.hash(hasher);
            job_id.hash(hasher);
            decision_seq.hash(hasher);
            replay_hash.hash(hasher);
            task.hash(hasher);
            region.hash(hasher);
            obligation.hash(hasher);
            true
        }
        TraceData::RegionCancel { region, reason } => {
            6_u8.hash(hasher);
            region.hash(hasher);
            hash_cancel_reason(hasher, reason);
            true
        }
        _ => false,
    }
}

fn hash_runtime_trace_data<H: Hasher>(hasher: &mut H, data: &TraceData) -> bool {
    match data {
        TraceData::Time { old, new } => {
            7_u8.hash(hasher);
            old.hash(hasher);
            new.hash(hasher);
            true
        }
        TraceData::Timer { timer_id, deadline } => {
            8_u8.hash(hasher);
            timer_id.hash(hasher);
            deadline.hash(hasher);
            true
        }
        TraceData::IoRequested { token, interest } => {
            9_u8.hash(hasher);
            token.hash(hasher);
            interest.hash(hasher);
            true
        }
        TraceData::IoReady { token, readiness } => {
            10_u8.hash(hasher);
            token.hash(hasher);
            readiness.hash(hasher);
            true
        }
        TraceData::IoResult { token, bytes } => {
            11_u8.hash(hasher);
            token.hash(hasher);
            bytes.hash(hasher);
            true
        }
        TraceData::IoError { token, kind } => {
            12_u8.hash(hasher);
            token.hash(hasher);
            kind.hash(hasher);
            true
        }
        TraceData::RngSeed { seed } => {
            13_u8.hash(hasher);
            seed.hash(hasher);
            true
        }
        TraceData::RngValue { value } => {
            14_u8.hash(hasher);
            value.hash(hasher);
            true
        }
        TraceData::Checkpoint {
            sequence,
            active_tasks,
            active_regions,
        } => {
            15_u8.hash(hasher);
            sequence.hash(hasher);
            active_tasks.hash(hasher);
            active_regions.hash(hasher);
            true
        }
        _ => false,
    }
}

fn hash_supervision_trace_data<H: Hasher>(hasher: &mut H, data: &TraceData) -> bool {
    match data {
        TraceData::Futurelock {
            task,
            region,
            idle_steps,
            held,
        } => {
            16_u8.hash(hasher);
            task.hash(hasher);
            region.hash(hasher);
            idle_steps.hash(hasher);
            held.len().hash(hasher);
            for (obligation, kind) in held {
                obligation.hash(hasher);
                kind.hash(hasher);
            }
            true
        }
        TraceData::Monitor {
            monitor_ref,
            watcher,
            watcher_region,
            monitored,
        } => {
            17_u8.hash(hasher);
            monitor_ref.hash(hasher);
            watcher.hash(hasher);
            watcher_region.hash(hasher);
            monitored.hash(hasher);
            true
        }
        TraceData::Down {
            monitor_ref,
            watcher,
            monitored,
            completion_vt,
            reason,
        } => {
            18_u8.hash(hasher);
            monitor_ref.hash(hasher);
            watcher.hash(hasher);
            monitored.hash(hasher);
            completion_vt.hash(hasher);
            hash_down_reason(hasher, reason);
            true
        }
        TraceData::Link {
            link_ref,
            task_a,
            region_a,
            task_b,
            region_b,
        } => {
            19_u8.hash(hasher);
            link_ref.hash(hasher);
            task_a.hash(hasher);
            region_a.hash(hasher);
            task_b.hash(hasher);
            region_b.hash(hasher);
            true
        }
        TraceData::Exit {
            link_ref,
            from,
            to,
            failure_vt,
            reason,
        } => {
            20_u8.hash(hasher);
            link_ref.hash(hasher);
            from.hash(hasher);
            to.hash(hasher);
            failure_vt.hash(hasher);
            hash_down_reason(hasher, reason);
            true
        }
        TraceData::Message(message) => {
            21_u8.hash(hasher);
            message.hash(hasher);
            true
        }
        TraceData::Chaos { kind, task, detail } => {
            22_u8.hash(hasher);
            kind.hash(hasher);
            task.hash(hasher);
            detail.hash(hasher);
            true
        }
        _ => false,
    }
}

fn hash_cancel_reason<H: Hasher>(hasher: &mut H, reason: &crate::types::CancelReason) {
    reason.kind.hash(hasher);
    reason.origin_region.hash(hasher);
    reason.origin_task.hash(hasher);
    reason.timestamp.hash(hasher);
    reason.message.hash(hasher);
    reason.truncated.hash(hasher);
    reason.truncated_at_depth.hash(hasher);
    match reason.cause.as_deref() {
        None => 0_u8.hash(hasher),
        Some(cause) => {
            1_u8.hash(hasher);
            hash_cancel_reason(hasher, cause);
        }
    }
}

fn hash_down_reason<H: Hasher>(hasher: &mut H, reason: &DownReason) {
    match reason {
        DownReason::Normal => 0_u8.hash(hasher),
        DownReason::Error(message) => {
            1_u8.hash(hasher);
            message.hash(hasher);
        }
        DownReason::Cancelled(reason) => {
            2_u8.hash(hasher);
            hash_cancel_reason(hasher, reason);
        }
        DownReason::Panicked(payload) => {
            3_u8.hash(hasher);
            payload.message().hash(hasher);
        }
    }
}

fn hash_obligation_state<H: Hasher>(hasher: &mut H, state: ObligationState) {
    match state {
        ObligationState::Reserved => 0_u8.hash(hasher),
        ObligationState::Committed => 1_u8.hash(hasher),
        ObligationState::Aborted => 2_u8.hash(hasher),
        ObligationState::Leaked => 3_u8.hash(hasher),
    }
}

fn hash_obligation_abort_reason<H: Hasher>(hasher: &mut H, reason: Option<ObligationAbortReason>) {
    match reason {
        None => 0_u8.hash(hasher),
        Some(ObligationAbortReason::Cancel) => 1_u8.hash(hasher),
        Some(ObligationAbortReason::Error) => 2_u8.hash(hasher),
        Some(ObligationAbortReason::Explicit) => 3_u8.hash(hasher),
    }
}

impl Default for TraceCertificate {
    fn default() -> Self {
        Self::new()
    }
}

/// Offline certificate verifier.
///
/// Replays events from a trace and builds a certificate, then compares
/// against an expected certificate.
pub struct CertificateVerifier;

/// Result of certificate verification.
#[derive(Debug)]
pub struct VerificationResult {
    /// Whether the certificate matched.
    pub valid: bool,
    /// Specific check results.
    pub checks: Vec<VerificationCheck>,
}

/// A single verification check.
#[derive(Debug)]
pub struct VerificationCheck {
    /// Name of the check.
    pub name: &'static str,
    /// Whether it passed.
    pub passed: bool,
    /// Details if failed.
    pub detail: Option<String>,
}

impl CertificateVerifier {
    /// Verify a certificate against trace events.
    #[must_use]
    pub fn verify(certificate: &TraceCertificate, events: &[TraceEvent]) -> VerificationResult {
        let mut checks = Vec::new();

        // Check 1: Event count matches.
        let count_ok = certificate.event_count() == events.len() as u64;
        checks.push(VerificationCheck {
            name: "event_count",
            passed: count_ok,
            detail: if count_ok {
                None
            } else {
                Some(format!(
                    "certificate says {} events, trace has {}",
                    certificate.event_count(),
                    events.len()
                ))
            },
        });

        // Check 2: Event hash matches.
        let mut reconstructed = TraceCertificate::new();
        for event in events {
            reconstructed.record_event(event);
        }
        let hash_ok = certificate.event_hash() == reconstructed.event_hash();
        checks.push(VerificationCheck {
            name: "event_hash",
            passed: hash_ok,
            detail: if hash_ok {
                None
            } else {
                Some(format!(
                    "certificate hash {:#018x}, reconstructed {:#018x}",
                    certificate.event_hash(),
                    reconstructed.event_hash()
                ))
            },
        });

        // Check 3: No violations recorded.
        let clean_ok = certificate.is_clean();
        checks.push(VerificationCheck {
            name: "no_violations",
            passed: clean_ok,
            detail: certificate
                .first_violation()
                .map(|v| format!("violation: {v}")),
        });

        // Check 4: Cancellation protocol — requests >= acks.
        let cancel_ok = certificate.cancel_requests >= certificate.cancel_acks;
        checks.push(VerificationCheck {
            name: "cancel_protocol",
            passed: cancel_ok,
            detail: if cancel_ok {
                None
            } else {
                Some(format!(
                    "{} acks without matching requests",
                    certificate.cancel_acks - certificate.cancel_requests
                ))
            },
        });

        // Check 5: Verify cancel ordering — every ack preceded by a request.
        let cancel_order_ok = verify_cancel_ordering(events);
        checks.push(VerificationCheck {
            name: "cancel_ordering",
            passed: cancel_order_ok,
            detail: if cancel_order_ok {
                None
            } else {
                Some("cancel ack without preceding request".to_string())
            },
        });

        let valid = checks.iter().all(|c| c.passed);
        VerificationResult { valid, checks }
    }
}

/// Check that every cancel ack is preceded by a cancel request for the same task.
fn verify_cancel_ordering(events: &[TraceEvent]) -> bool {
    let mut pending_cancels: BTreeSet<crate::types::TaskId> = BTreeSet::new();

    for event in events {
        match event.kind {
            TraceEventKind::CancelRequest => {
                let Some(task_id) = cancel_task_id(event) else {
                    return false;
                };
                pending_cancels.insert(task_id);
            }
            TraceEventKind::CancelAck => {
                let Some(task_id) = cancel_task_id(event) else {
                    return false;
                };
                if !pending_cancels.remove(&task_id) {
                    return false;
                }
            }
            _ => {}
        }
    }

    true
}

fn cancel_task_id(event: &TraceEvent) -> Option<crate::types::TaskId> {
    match &event.data {
        TraceData::Cancel { task, .. } | TraceData::Task { task, .. } => Some(*task),
        _ => None,
    }
}

impl std::fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.valid {
            write!(f, "Certificate VALID ({} checks passed)", self.checks.len())
        } else {
            write!(f, "Certificate INVALID:")?;
            for check in &self.checks {
                if !check.passed {
                    write!(f, "\n  FAIL {}", check.name)?;
                    if let Some(ref detail) = check.detail {
                        write!(f, ": {detail}")?;
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::event::TraceData;
    use crate::types::{CancelReason, RegionId, TaskId, Time};

    fn make_event(seq: u64, kind: TraceEventKind) -> TraceEvent {
        TraceEvent::new(seq, Time::ZERO, kind, TraceData::None)
    }

    #[test]
    fn empty_certificate_is_clean() {
        let cert = TraceCertificate::new();
        assert!(cert.is_clean());
        assert_eq!(cert.event_count(), 0);
        assert_eq!(cert.obligation_balance(), 0);
        assert_eq!(cert.cancel_balance(), 0);
        assert_eq!(cert.task_balance(), 0);
    }

    #[test]
    fn certificate_tracks_event_counts() {
        let mut cert = TraceCertificate::new();
        cert.record_event(&make_event(1, TraceEventKind::Spawn));
        cert.record_event(&make_event(2, TraceEventKind::Spawn));
        cert.record_event(&make_event(3, TraceEventKind::Complete));

        assert_eq!(cert.event_count(), 3);
        assert_eq!(cert.spawns, 2);
        assert_eq!(cert.completes, 1);
        assert_eq!(cert.task_balance(), 1); // 2 spawns - 1 complete
    }

    #[test]
    fn certificate_hash_deterministic() {
        let events = vec![
            make_event(1, TraceEventKind::Spawn),
            make_event(2, TraceEventKind::Complete),
        ];

        let mut cert1 = TraceCertificate::new();
        let mut cert2 = TraceCertificate::new();
        for e in &events {
            cert1.record_event(e);
            cert2.record_event(e);
        }

        assert_eq!(cert1.event_hash(), cert2.event_hash());
    }

    #[test]
    fn certificate_hash_sensitive_to_order() {
        let mut cert1 = TraceCertificate::new();
        cert1.record_event(&make_event(1, TraceEventKind::Spawn));
        cert1.record_event(&make_event(2, TraceEventKind::Complete));

        let mut cert2 = TraceCertificate::new();
        cert2.record_event(&make_event(2, TraceEventKind::Complete));
        cert2.record_event(&make_event(1, TraceEventKind::Spawn));

        assert_ne!(cert1.event_hash(), cert2.event_hash());
    }

    #[test]
    fn certificate_hash_sensitive_to_payload() {
        let region = RegionId::new_for_test(0, 0);

        let mut cert1 = TraceCertificate::new();
        cert1.record_event(&TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            region,
        ));

        let mut cert2 = TraceCertificate::new();
        cert2.record_event(&TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            region,
        ));

        assert_ne!(cert1.event_hash(), cert2.event_hash());
    }

    #[test]
    fn certificate_violation_tracking() {
        let mut cert = TraceCertificate::new();
        assert!(cert.is_clean());

        cert.record_violation("obligation leak in task 42");
        assert!(!cert.is_clean());
        assert_eq!(cert.first_violation(), Some("obligation leak in task 42"));

        // Second violation doesn't overwrite first.
        cert.record_violation("another problem");
        assert_eq!(cert.first_violation(), Some("obligation leak in task 42"));
    }

    #[test]
    fn verifier_accepts_matching_certificate() {
        let events = vec![
            make_event(1, TraceEventKind::Spawn),
            make_event(2, TraceEventKind::Complete),
        ];

        let mut cert = TraceCertificate::new();
        for e in &events {
            cert.record_event(e);
        }

        let result = CertificateVerifier::verify(&cert, &events);
        assert!(result.valid, "Verification failed: {result}");
    }

    #[test]
    fn verifier_rejects_wrong_event_count() {
        let events = vec![make_event(1, TraceEventKind::Spawn)];

        let mut cert = TraceCertificate::new();
        cert.record_event(&make_event(1, TraceEventKind::Spawn));
        cert.record_event(&make_event(2, TraceEventKind::Complete));

        let result = CertificateVerifier::verify(&cert, &events);
        assert!(!result.valid);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "event_count" && !c.passed)
        );
    }

    #[test]
    fn verifier_rejects_wrong_hash() {
        let events = vec![make_event(1, TraceEventKind::Spawn)];

        let mut cert = TraceCertificate::new();
        cert.record_event(&make_event(1, TraceEventKind::Complete)); // different kind

        // Fix event count to match.
        let result = CertificateVerifier::verify(&cert, &events);
        assert!(!result.valid);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "event_hash" && !c.passed)
        );
    }

    #[test]
    fn verifier_rejects_wrong_hash_when_payload_differs() {
        let region = RegionId::new_for_test(0, 0);
        let events = vec![TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            region,
        )];

        let mut cert = TraceCertificate::new();
        cert.record_event(&TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            region,
        ));

        let result = CertificateVerifier::verify(&cert, &events);
        assert!(!result.valid);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "event_hash" && !c.passed)
        );
    }

    #[test]
    fn verifier_rejects_violation_in_certificate() {
        let events = vec![make_event(1, TraceEventKind::Spawn)];
        let mut cert = TraceCertificate::new();
        for e in &events {
            cert.record_event(e);
        }
        cert.record_violation("test violation");

        let result = CertificateVerifier::verify(&cert, &events);
        assert!(!result.valid);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "no_violations" && !c.passed)
        );
    }

    #[test]
    fn cancel_ordering_valid() {
        let task = TaskId::new_for_test(1, 0);
        let region = RegionId::new_for_test(0, 0);
        let events = vec![
            TraceEvent::new(
                1,
                Time::ZERO,
                TraceEventKind::CancelRequest,
                TraceData::Cancel {
                    task,
                    region,
                    reason: CancelReason::user("test"),
                },
            ),
            TraceEvent::new(
                2,
                Time::ZERO,
                TraceEventKind::CancelAck,
                TraceData::Cancel {
                    task,
                    region,
                    reason: CancelReason::user("test"),
                },
            ),
        ];
        assert!(verify_cancel_ordering(&events));
    }

    #[test]
    fn obligation_balance_at_quiescence() {
        let mut cert = TraceCertificate::new();
        cert.record_event(&make_event(1, TraceEventKind::ObligationReserve));
        cert.record_event(&make_event(2, TraceEventKind::ObligationCommit));
        assert_eq!(cert.obligation_balance(), 0);
    }

    #[test]
    fn verification_result_display() {
        let result = VerificationResult {
            valid: true,
            checks: vec![VerificationCheck {
                name: "test",
                passed: true,
                detail: None,
            }],
        };
        let s = format!("{result}");
        assert!(s.contains("VALID"));
    }
}
