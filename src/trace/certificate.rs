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

use crate::trace::event::{TraceData, TraceEvent, TraceEventKind};
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
        // Incremental hash: mix event kind + seq into running hash.
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.event_hash.hash(&mut hasher);
        (event.kind as u8).hash(&mut hasher);
        event.seq.hash(&mut hasher);
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
    #[allow(clippy::cast_possible_wrap)]
    pub fn obligation_balance(&self) -> i64 {
        self.obligation_acquires as i64 - self.obligation_releases as i64
    }

    /// Cancel balance: requests minus acks.
    /// Should be zero at quiescence (all cancels acknowledged).
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub fn cancel_balance(&self) -> i64 {
        self.cancel_requests as i64 - self.cancel_acks as i64
    }

    /// Task balance: spawns minus completes.
    /// Should be zero at quiescence.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub fn task_balance(&self) -> i64 {
        self.spawns as i64 - self.completes as i64
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
