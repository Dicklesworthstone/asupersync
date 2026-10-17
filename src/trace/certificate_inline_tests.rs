    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
