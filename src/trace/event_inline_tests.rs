    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::monitor::DownReason;
    use crate::record::{ObligationAbortReason, ObligationKind, ObligationState};
    use crate::trace::distributed::LamportTime;
    use crate::types::CancelReason;
    use serde_json::Value;
    use std::collections::BTreeSet;

    fn task(n: u32) -> TaskId {
        TaskId::new_for_test(n, 1)
    }
    fn region(n: u32) -> RegionId {
        RegionId::new_for_test(n, 1)
    }
    fn obligation(n: u32) -> ObligationId {
        ObligationId::new_for_test(n, 1)
    }

    fn scrub_browser_trace_fields(fields: &std::collections::BTreeMap<String, String>) -> Value {
        let mut value = serde_json::to_value(fields).expect("serialize browser trace fields");
        let obj = value
            .as_object_mut()
            .expect("browser trace fields serialize to an object");

        for key in [
            "capture_host_time_ns",
            "capture_replay_key",
            "completion_vt",
            "deadline",
            "failure_vt",
            "from",
            "monitored",
            "new",
            "old",
            "parent",
            "region_a",
            "region_b",
            "seq",
            "task_a",
            "task_b",
            "to",
            "time_ns",
            "trace_id",
            "task",
            "region",
            "obligation",
            "sequence_group",
            "watcher",
            "watcher_region",
        ] {
            if obj.contains_key(key) {
                obj.insert(key.to_string(), Value::String(format!("[{key}]")));
            }
        }

        value
    }

    // ── TraceEventKind basics ──────────────────────────────────────

    #[test]
    fn trace_event_version_is_set() {
        let event = TraceEvent::new(1, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        assert_eq!(event.version, TRACE_EVENT_SCHEMA_VERSION);
    }

    #[test]
    fn trace_event_kind_stable_names_are_unique() {
        let mut names = BTreeSet::new();
        for kind in TraceEventKind::ALL {
            assert!(names.insert(kind.stable_name()));
        }
    }

    #[test]
    fn trace_event_taxonomy_is_documented() {
        const DOC: &str = include_str!("../../docs/spork_deterministic_ordering.md");
        for kind in TraceEventKind::ALL {
            let marker = format!("- `{}` => `{}`", kind.stable_name(), kind.required_fields());
            assert!(
                DOC.contains(&marker),
                "missing taxonomy entry in docs/spork_deterministic_ordering.md for {}",
                kind.stable_name()
            );
        }
    }

    #[test]
    fn all_array_has_42_kinds() {
        assert_eq!(TraceEventKind::ALL.len(), 45);
    }

    #[test]
    fn all_kinds_are_distinct() {
        let set: BTreeSet<TraceEventKind> = TraceEventKind::ALL.iter().copied().collect();
        assert_eq!(set.len(), TraceEventKind::ALL.len());
    }

    #[test]
    fn display_delegates_to_stable_name() {
        for kind in TraceEventKind::ALL {
            assert_eq!(format!("{kind}"), kind.stable_name());
        }
    }

    #[test]
    fn kind_ord_is_consistent_with_eq() {
        for a in TraceEventKind::ALL {
            for b in TraceEventKind::ALL {
                if a == b {
                    assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
                } else {
                    assert_ne!(a.cmp(&b), std::cmp::Ordering::Equal);
                }
            }
        }
    }

    #[test]
    fn required_fields_non_empty_for_all() {
        for kind in TraceEventKind::ALL {
            assert!(
                !kind.required_fields().is_empty(),
                "required_fields empty for {kind:?}"
            );
        }
    }

    // ── Constructor tests ──────────────────────────────────────────

    #[test]
    fn spawn_constructor() {
        let e = TraceEvent::spawn(1, Time::ZERO, task(10), region(20));
        assert_eq!(e.kind, TraceEventKind::Spawn);
        assert_eq!(e.seq, 1);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(10),
                region: region(20)
            }
        );
    }

    #[test]
    fn schedule_constructor() {
        let e = TraceEvent::schedule(2, Time::from_nanos(100), task(1), region(2));
        assert_eq!(e.kind, TraceEventKind::Schedule);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(1),
                region: region(2)
            }
        );
    }

    #[test]
    fn yield_task_constructor() {
        let e = TraceEvent::yield_task(3, Time::ZERO, task(5), region(6));
        assert_eq!(e.kind, TraceEventKind::Yield);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(5),
                region: region(6)
            }
        );
    }

    #[test]
    fn wake_constructor() {
        let e = TraceEvent::wake(4, Time::ZERO, task(7), region(8));
        assert_eq!(e.kind, TraceEventKind::Wake);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(7),
                region: region(8)
            }
        );
    }

    #[test]
    fn poll_constructor() {
        let e = TraceEvent::poll(5, Time::ZERO, task(9), region(10));
        assert_eq!(e.kind, TraceEventKind::Poll);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(9),
                region: region(10)
            }
        );
    }

    #[test]
    fn complete_constructor() {
        let e = TraceEvent::complete(6, Time::ZERO, task(11), region(12));
        assert_eq!(e.kind, TraceEventKind::Complete);
        assert_eq!(
            e.data,
            TraceData::Task {
                task: task(11),
                region: region(12)
            }
        );
    }

    #[test]
    fn cancel_request_constructor() {
        let e =
            TraceEvent::cancel_request(7, Time::ZERO, task(1), region(2), CancelReason::timeout());
        assert_eq!(e.kind, TraceEventKind::CancelRequest);
        match &e.data {
            TraceData::Cancel {
                task: t,
                region: r,
                reason,
            } => {
                assert_eq!(*t, task(1));
                assert_eq!(*r, region(2));
                assert_eq!(reason.kind(), crate::types::CancelKind::Timeout);
            }
            other => panic!("expected Cancel, got {other:?}"),
        }
    }

    #[test]
    fn region_created_constructor_with_parent() {
        let e = TraceEvent::region_created(8, Time::ZERO, region(3), Some(region(1)));
        assert_eq!(e.kind, TraceEventKind::RegionCreated);
        assert_eq!(
            e.data,
            TraceData::Region {
                region: region(3),
                parent: Some(region(1))
            }
        );
    }

    #[test]
    fn region_created_constructor_without_parent() {
        let e = TraceEvent::region_created(9, Time::ZERO, region(3), None);
        assert_eq!(e.kind, TraceEventKind::RegionCreated);
        assert_eq!(
            e.data,
            TraceData::Region {
                region: region(3),
                parent: None
            }
        );
    }

    #[test]
    fn region_cancelled_constructor() {
        let e = TraceEvent::region_cancelled(10, Time::ZERO, region(5), CancelReason::shutdown());
        assert_eq!(e.kind, TraceEventKind::RegionCancelled);
        match &e.data {
            TraceData::RegionCancel { region: r, .. } => assert_eq!(*r, region(5)),
            other => panic!("expected RegionCancel, got {other:?}"),
        }
    }

    #[test]
    fn time_advance_constructor() {
        let e =
            TraceEvent::time_advance(11, Time::ZERO, Time::from_nanos(0), Time::from_nanos(100));
        assert_eq!(e.kind, TraceEventKind::TimeAdvance);
        assert_eq!(
            e.data,
            TraceData::Time {
                old: Time::from_nanos(0),
                new: Time::from_nanos(100)
            }
        );
    }

    #[test]
    fn timer_scheduled_constructor() {
        let e = TraceEvent::timer_scheduled(12, Time::ZERO, 42, Time::from_millis(500));
        assert_eq!(e.kind, TraceEventKind::TimerScheduled);
        assert_eq!(
            e.data,
            TraceData::Timer {
                timer_id: 42,
                deadline: Some(Time::from_millis(500))
            }
        );
    }

    #[test]
    fn timer_fired_constructor() {
        let e = TraceEvent::timer_fired(13, Time::ZERO, 42);
        assert_eq!(e.kind, TraceEventKind::TimerFired);
        assert_eq!(
            e.data,
            TraceData::Timer {
                timer_id: 42,
                deadline: None
            }
        );
    }

    #[test]
    fn timer_cancelled_constructor() {
        let e = TraceEvent::timer_cancelled(14, Time::ZERO, 42);
        assert_eq!(e.kind, TraceEventKind::TimerCancelled);
        assert_eq!(
            e.data,
            TraceData::Timer {
                timer_id: 42,
                deadline: None
            }
        );
    }

    #[test]
    fn io_requested_constructor() {
        let e = TraceEvent::io_requested(15, Time::ZERO, 99, 0x03);
        assert_eq!(e.kind, TraceEventKind::IoRequested);
        assert_eq!(
            e.data,
            TraceData::IoRequested {
                token: 99,
                interest: 0x03
            }
        );
    }

    #[test]
    fn io_ready_constructor() {
        let e = TraceEvent::io_ready(16, Time::ZERO, 99, 0x01);
        assert_eq!(e.kind, TraceEventKind::IoReady);
        assert_eq!(
            e.data,
            TraceData::IoReady {
                token: 99,
                readiness: 0x01
            }
        );
    }

    #[test]
    fn io_result_constructor() {
        let e = TraceEvent::io_result(17, Time::ZERO, 99, 1024);
        assert_eq!(e.kind, TraceEventKind::IoResult);
        assert_eq!(
            e.data,
            TraceData::IoResult {
                token: 99,
                bytes: 1024
            }
        );
    }

    #[test]
    fn io_result_negative_bytes() {
        let e = TraceEvent::io_result(18, Time::ZERO, 99, -1);
        assert_eq!(
            e.data,
            TraceData::IoResult {
                token: 99,
                bytes: -1
            }
        );
    }

    #[test]
    fn io_error_constructor() {
        let e = TraceEvent::io_error(19, Time::ZERO, 99, 13);
        assert_eq!(e.kind, TraceEventKind::IoError);
        assert_eq!(
            e.data,
            TraceData::IoError {
                token: 99,
                kind: 13
            }
        );
    }

    #[test]
    fn rng_seed_constructor() {
        let e = TraceEvent::rng_seed(20, Time::ZERO, 0xDEAD_BEEF);
        assert_eq!(e.kind, TraceEventKind::RngSeed);
        assert_eq!(e.data, TraceData::RngSeed { seed: 0xDEAD_BEEF });
    }

    #[test]
    fn rng_value_constructor() {
        let e = TraceEvent::rng_value(21, Time::ZERO, 42);
        assert_eq!(e.kind, TraceEventKind::RngValue);
        assert_eq!(e.data, TraceData::RngValue { value: 42 });
    }

    #[test]
    fn checkpoint_constructor() {
        let e = TraceEvent::checkpoint(22, Time::ZERO, 7, 3, 2);
        assert_eq!(e.kind, TraceEventKind::Checkpoint);
        assert_eq!(
            e.data,
            TraceData::Checkpoint {
                sequence: 7,
                active_tasks: 3,
                active_regions: 2
            }
        );
    }

    #[test]
    fn obligation_reserve_constructor() {
        let e = TraceEvent::obligation_reserve(
            23,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::SendPermit,
        );
        assert_eq!(e.kind, TraceEventKind::ObligationReserve);
        match &e.data {
            TraceData::Obligation {
                state,
                duration_ns,
                abort_reason,
                ..
            } => {
                assert_eq!(*state, ObligationState::Reserved);
                assert_eq!(*duration_ns, None);
                assert_eq!(*abort_reason, None);
            }
            other => panic!("expected Obligation, got {other:?}"),
        }
    }

    #[test]
    fn obligation_commit_constructor() {
        let e = TraceEvent::obligation_commit(
            24,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::Ack,
            5000,
        );
        assert_eq!(e.kind, TraceEventKind::ObligationCommit);
        match &e.data {
            TraceData::Obligation {
                state,
                duration_ns,
                abort_reason,
                ..
            } => {
                assert_eq!(*state, ObligationState::Committed);
                assert_eq!(*duration_ns, Some(5000));
                assert_eq!(*abort_reason, None);
            }
            other => panic!("expected Obligation, got {other:?}"),
        }
    }

    #[test]
    fn obligation_abort_constructor() {
        let e = TraceEvent::obligation_abort(
            25,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::Lease,
            3000,
            ObligationAbortReason::Cancel,
        );
        assert_eq!(e.kind, TraceEventKind::ObligationAbort);
        match &e.data {
            TraceData::Obligation {
                state,
                duration_ns,
                abort_reason,
                ..
            } => {
                assert_eq!(*state, ObligationState::Aborted);
                assert_eq!(*duration_ns, Some(3000));
                assert_eq!(*abort_reason, Some(ObligationAbortReason::Cancel));
            }
            other => panic!("expected Obligation, got {other:?}"),
        }
    }

    #[test]
    fn obligation_leak_constructor() {
        let e = TraceEvent::obligation_leak(
            26,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::IoOp,
            9000,
        );
        assert_eq!(e.kind, TraceEventKind::ObligationLeak);
        match &e.data {
            TraceData::Obligation {
                state,
                duration_ns,
                abort_reason,
                ..
            } => {
                assert_eq!(*state, ObligationState::Leaked);
                assert_eq!(*duration_ns, Some(9000));
                assert_eq!(*abort_reason, None);
            }
            other => panic!("expected Obligation, got {other:?}"),
        }
    }

    #[test]
    fn monitor_created_constructor() {
        let e = TraceEvent::monitor_created(27, Time::ZERO, 100, task(1), region(2), task(3));
        assert_eq!(e.kind, TraceEventKind::MonitorCreated);
        assert_eq!(
            e.data,
            TraceData::Monitor {
                monitor_ref: 100,
                watcher: task(1),
                watcher_region: region(2),
                monitored: task(3),
            }
        );
    }

    #[test]
    fn monitor_dropped_constructor() {
        let e = TraceEvent::monitor_dropped(28, Time::ZERO, 100, task(1), region(2), task(3));
        assert_eq!(e.kind, TraceEventKind::MonitorDropped);
        assert_eq!(
            e.data,
            TraceData::Monitor {
                monitor_ref: 100,
                watcher: task(1),
                watcher_region: region(2),
                monitored: task(3),
            }
        );
    }

    #[test]
    fn down_delivered_constructor() {
        let e = TraceEvent::down_delivered(
            29,
            Time::ZERO,
            100,
            task(1),
            task(3),
            Time::from_nanos(500),
            DownReason::Normal,
        );
        assert_eq!(e.kind, TraceEventKind::DownDelivered);
        assert_eq!(
            e.data,
            TraceData::Down {
                monitor_ref: 100,
                watcher: task(1),
                monitored: task(3),
                completion_vt: Time::from_nanos(500),
                reason: DownReason::Normal,
            }
        );
    }

    #[test]
    fn link_created_constructor() {
        let e =
            TraceEvent::link_created(30, Time::ZERO, 200, task(1), region(2), task(3), region(4));
        assert_eq!(e.kind, TraceEventKind::LinkCreated);
        assert_eq!(
            e.data,
            TraceData::Link {
                link_ref: 200,
                task_a: task(1),
                region_a: region(2),
                task_b: task(3),
                region_b: region(4),
            }
        );
    }

    #[test]
    fn link_dropped_constructor() {
        let e =
            TraceEvent::link_dropped(31, Time::ZERO, 200, task(1), region(2), task(3), region(4));
        assert_eq!(e.kind, TraceEventKind::LinkDropped);
        assert_eq!(
            e.data,
            TraceData::Link {
                link_ref: 200,
                task_a: task(1),
                region_a: region(2),
                task_b: task(3),
                region_b: region(4),
            }
        );
    }

    #[test]
    fn exit_delivered_constructor() {
        let e = TraceEvent::exit_delivered(
            32,
            Time::ZERO,
            200,
            task(1),
            task(3),
            Time::from_nanos(999),
            DownReason::Normal,
        );
        assert_eq!(e.kind, TraceEventKind::ExitDelivered);
        assert_eq!(
            e.data,
            TraceData::Exit {
                link_ref: 200,
                from: task(1),
                to: task(3),
                failure_vt: Time::from_nanos(999),
                reason: DownReason::Normal,
            }
        );
    }

    #[test]
    fn user_trace_constructor() {
        let e = TraceEvent::user_trace(33, Time::ZERO, "hello");
        assert_eq!(e.kind, TraceEventKind::UserTrace);
        assert_eq!(e.data, TraceData::Message("hello".into()));
    }

    #[test]
    fn obligation_handoff_typed_message_preserves_generations_and_envelope() {
        let handoff = ObligationHandoff {
            id: obligation(7),
            source_ticket: 9,
            destination_ticket: 12,
            source_holder: task(2),
            destination_holder: TaskId::new_for_test(2, 3),
            source_region: region(4),
            destination_region: RegionId::new_for_test(4, 5),
        };
        let event = TraceEvent::obligation_handoff(21, Time::from_nanos(31), &handoff);
        assert_eq!(event.kind, TraceEventKind::UserTrace);
        assert_eq!(event.version, TRACE_EVENT_SCHEMA_VERSION);
        assert_eq!(decode_obligation_handoff(&event).unwrap(), Some(handoff));
        let outer = serde_json::to_vec(&event).unwrap();
        let decoded: TraceEvent = serde_json::from_slice(&outer).unwrap();
        assert_eq!(decoded, event);
        assert_eq!(
            decode_obligation_handoff(&decoded),
            decode_obligation_handoff(&event)
        );
        assert_eq!(redact_browser_trace_event(&event), event);
        let invalid = TraceEvent::user_trace(
            22,
            Time::ZERO,
            "obligation_handoff_v1 {\"secret\":\"must-not-leak\"}",
        );
        let redacted = redact_browser_trace_event(&invalid);
        assert!(decode_obligation_handoff(&redacted).is_err());
        let TraceData::Message(message) = redacted.data else {
            panic!("retained envelope")
        };
        assert!(!message.contains("must-not-leak"));
        assert!(!message.contains("secret"));
    }

    #[test]
    fn obligation_handoff_parser_refuses_malformed_ambiguous_and_oversized_messages() {
        let handoff = ObligationHandoff {
            id: obligation(1),
            source_ticket: 3,
            destination_ticket: 4,
            source_holder: task(1),
            destination_holder: task(2),
            source_region: region(1),
            destination_region: region(2),
        };
        let payload = serde_json::to_string(&handoff).unwrap();
        let mut missing = serde_json::to_value(&handoff).unwrap();
        missing.as_object_mut().unwrap().remove("source_holder");
        let mut unknown = serde_json::to_value(&handoff).unwrap();
        unknown["ignored_authority"] = Value::Bool(true);
        let messages = [
            "obligation_handoff_v2 {}".to_owned(),
            "obligation_handoff_v1 {}".to_owned(),
            format!("{OBLIGATION_HANDOFF_PREFIX}{payload} {{}}"),
            format!(
                "{OBLIGATION_HANDOFF_PREFIX}{{\"source_ticket\":3,{}",
                &payload[1..]
            ),
            format!("{OBLIGATION_HANDOFF_PREFIX}{missing}"),
            format!("{OBLIGATION_HANDOFF_PREFIX}{unknown}"),
            format!(
                "{OBLIGATION_HANDOFF_PREFIX}{payload}{}",
                " ".repeat(MAX_OBLIGATION_HANDOFF_MESSAGE_BYTES)
            ),
        ];
        for message in messages {
            assert!(
                decode_obligation_handoff(&TraceEvent::user_trace(1, Time::ZERO, &message))
                    .is_err(),
                "{message}"
            );
        }
        let mut same_holder = handoff.clone();
        same_holder.destination_holder = same_holder.source_holder;
        assert!(
            decode_obligation_handoff(&TraceEvent::obligation_handoff(1, Time::ZERO, &same_holder))
                .is_err()
        );
        let mut old_ticket = handoff.clone();
        old_ticket.destination_ticket = old_ticket.source_ticket;
        assert!(
            decode_obligation_handoff(&TraceEvent::obligation_handoff(1, Time::ZERO, &old_ticket))
                .is_err()
        );
        let mut wrong_envelope = TraceEvent::obligation_handoff(1, Time::ZERO, &handoff);
        wrong_envelope.kind = TraceEventKind::Checkpoint;
        assert!(decode_obligation_handoff(&wrong_envelope).is_err());
        wrong_envelope.kind = TraceEventKind::UserTrace;
        wrong_envelope.version += 1;
        assert!(decode_obligation_handoff(&wrong_envelope).is_err());
        assert_eq!(
            decode_obligation_handoff(&TraceEvent::user_trace(1, Time::ZERO, "ordinary {bad json")),
            Ok(None)
        );
    }

    #[test]
    fn user_trace_accepts_string() {
        let e = TraceEvent::user_trace(34, Time::ZERO, String::from("world"));
        assert_eq!(e.data, TraceData::Message("world".into()));
    }

    #[test]
    fn worker_lifecycle_constructors_preserve_payload_shape() {
        let e = TraceEvent::worker_cancel_requested(
            35,
            Time::ZERO,
            "worker-a",
            77,
            91,
            0x00C0_FFEE,
            task(9),
            region(10),
            obligation(11),
        );
        assert_eq!(e.kind, TraceEventKind::WorkerCancelRequested);
        assert_eq!(
            e.data,
            TraceData::Worker {
                worker_id: "worker-a".into(),
                job_id: 77,
                decision_seq: 91,
                replay_hash: 0x00C0_FFEE,
                task: task(9),
                region: region(10),
                obligation: obligation(11),
            }
        );
    }

    // ── with_logical_time ──────────────────────────────────────────

    #[test]
    fn with_logical_time_sets_field() {
        let lt = LogicalTime::Lamport(LamportTime::from_raw(42));
        let e = TraceEvent::new(1, Time::ZERO, TraceEventKind::UserTrace, TraceData::None)
            .with_logical_time(lt);
        assert_eq!(
            e.logical_time,
            Some(LogicalTime::Lamport(LamportTime::from_raw(42)))
        );
    }

    #[test]
    fn default_logical_time_is_none() {
        let e = TraceEvent::new(1, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        assert_eq!(e.logical_time, None);
    }

    // ── Display formatting ─────────────────────────────────────────

    #[test]
    fn display_task_event() {
        let e = TraceEvent::spawn(1, Time::ZERO, task(10), region(20));
        let s = format!("{e}");
        assert!(s.contains("spawn"), "expected 'spawn' in {s}");
        assert!(s.contains("[000001]"), "expected seq in {s}");
    }

    #[test]
    fn display_region_with_parent() {
        let e = TraceEvent::region_created(2, Time::ZERO, region(3), Some(region(1)));
        let s = format!("{e}");
        assert!(s.contains("region_created"), "expected kind in {s}");
        assert!(s.contains("parent"), "expected parent in {s}");
    }

    #[test]
    fn display_region_without_parent() {
        let e = TraceEvent::region_created(3, Time::ZERO, region(3), None);
        let s = format!("{e}");
        assert!(s.contains("region_created"), "expected kind in {s}");
        assert!(!s.contains("parent"), "should not contain parent: {s}");
    }

    #[test]
    fn display_obligation_with_duration_and_abort() {
        let e = TraceEvent::obligation_abort(
            4,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::Lease,
            5000,
            ObligationAbortReason::Error,
        );
        let s = format!("{e}");
        assert!(s.contains("obligation_abort"), "expected kind in {s}");
        assert!(s.contains("duration=5000ns"), "expected duration in {s}");
        assert!(s.contains("abort_reason="), "expected abort_reason in {s}");
    }

    #[test]
    fn display_obligation_reserve_no_duration() {
        let e = TraceEvent::obligation_reserve(
            5,
            Time::ZERO,
            obligation(1),
            task(2),
            region(3),
            ObligationKind::SendPermit,
        );
        let s = format!("{e}");
        assert!(
            !s.contains("duration="),
            "reserve should not show duration: {s}"
        );
        assert!(
            !s.contains("abort_reason="),
            "reserve should not show abort_reason: {s}"
        );
    }

    #[test]
    fn display_cancel_event() {
        let e =
            TraceEvent::cancel_request(6, Time::ZERO, task(1), region(2), CancelReason::timeout());
        let s = format!("{e}");
        assert!(s.contains("cancel_request"), "expected kind in {s}");
        assert!(s.contains("reason="), "expected reason in {s}");
    }

    #[test]
    fn display_region_cancel() {
        let e = TraceEvent::region_cancelled(7, Time::ZERO, region(5), CancelReason::shutdown());
        let s = format!("{e}");
        assert!(s.contains("region_cancelled"), "expected kind in {s}");
        assert!(s.contains("reason="), "expected reason in {s}");
    }

    #[test]
    fn display_time_advance() {
        let e = TraceEvent::time_advance(8, Time::ZERO, Time::from_nanos(0), Time::from_nanos(100));
        let s = format!("{e}");
        assert!(s.contains("time_advance"), "expected kind in {s}");
        assert!(s.contains("->"), "expected arrow in {s}");
    }

    #[test]
    fn display_timer_with_deadline() {
        let e = TraceEvent::timer_scheduled(9, Time::ZERO, 42, Time::from_millis(500));
        let s = format!("{e}");
        assert!(s.contains("timer=42"), "expected timer id in {s}");
        assert!(s.contains("deadline="), "expected deadline in {s}");
    }

    #[test]
    fn display_timer_without_deadline() {
        let e = TraceEvent::timer_fired(10, Time::ZERO, 42);
        let s = format!("{e}");
        assert!(s.contains("timer=42"), "expected timer id in {s}");
        assert!(!s.contains("deadline="), "should not show deadline: {s}");
    }

    #[test]
    fn display_io_requested() {
        let e = TraceEvent::io_requested(11, Time::ZERO, 99, 0x03);
        let s = format!("{e}");
        assert!(s.contains("io_requested"), "expected kind in {s}");
        assert!(s.contains("token=99"), "expected token in {s}");
        assert!(s.contains("interest=3"), "expected interest in {s}");
    }

    #[test]
    fn display_io_ready() {
        let e = TraceEvent::io_ready(12, Time::ZERO, 99, 0x01);
        let s = format!("{e}");
        assert!(s.contains("io_ready"), "expected kind in {s}");
        assert!(s.contains("readiness=1"), "expected readiness in {s}");
    }

    #[test]
    fn display_io_result() {
        let e = TraceEvent::io_result(13, Time::ZERO, 99, 1024);
        let s = format!("{e}");
        assert!(s.contains("io_result"), "expected kind in {s}");
        assert!(s.contains("bytes=1024"), "expected bytes in {s}");
    }

    #[test]
    fn display_io_error() {
        let e = TraceEvent::io_error(14, Time::ZERO, 99, 13);
        let s = format!("{e}");
        assert!(s.contains("io_error"), "expected kind in {s}");
        assert!(s.contains("kind=13"), "expected kind in {s}");
    }

    #[test]
    fn display_rng_seed() {
        let e = TraceEvent::rng_seed(15, Time::ZERO, 0xCAFE);
        let s = format!("{e}");
        assert!(s.contains("rng_seed=51966"), "expected seed in {s}");
    }

    #[test]
    fn display_rng_value() {
        let e = TraceEvent::rng_value(16, Time::ZERO, 42);
        let s = format!("{e}");
        assert!(s.contains("rng_value=42"), "expected value in {s}");
    }

    #[test]
    fn display_checkpoint() {
        let e = TraceEvent::checkpoint(17, Time::ZERO, 7, 3, 2);
        let s = format!("{e}");
        assert!(s.contains("checkpoint"), "expected kind in {s}");
        assert!(s.contains("seq=7"), "expected seq in {s}");
        assert!(s.contains("tasks=3"), "expected tasks in {s}");
        assert!(s.contains("regions=2"), "expected regions in {s}");
    }

    #[test]
    fn display_futurelock_empty_held() {
        let e = TraceEvent::new(
            18,
            Time::ZERO,
            TraceEventKind::FuturelockDetected,
            TraceData::Futurelock {
                task: task(1),
                region: region(2),
                idle_steps: 10,
                held: vec![],
            },
        );
        let s = format!("{e}");
        assert!(s.contains("futurelock"), "expected kind in {s}");
        assert!(s.contains("idle=10"), "expected idle in {s}");
        assert!(s.contains("held=[]"), "expected empty held in {s}");
    }

    #[test]
    fn display_futurelock_with_held() {
        let e = TraceEvent::new(
            19,
            Time::ZERO,
            TraceEventKind::FuturelockDetected,
            TraceData::Futurelock {
                task: task(1),
                region: region(2),
                idle_steps: 5,
                held: vec![(obligation(10), ObligationKind::SendPermit)],
            },
        );
        let s = format!("{e}");
        assert!(s.contains("held=["), "expected held in {s}");
        assert!(s.contains("SendPermit"), "expected kind in {s}");
    }

    #[test]
    fn display_monitor() {
        let e = TraceEvent::monitor_created(20, Time::ZERO, 100, task(1), region(2), task(3));
        let s = format!("{e}");
        assert!(s.contains("monitor_ref=100"), "expected ref in {s}");
    }

    #[test]
    fn display_down() {
        let e = TraceEvent::down_delivered(
            21,
            Time::ZERO,
            100,
            task(1),
            task(3),
            Time::from_nanos(500),
            DownReason::Normal,
        );
        let s = format!("{e}");
        assert!(s.contains("down"), "expected down in {s}");
        assert!(s.contains("monitor_ref=100"), "expected ref in {s}");
    }

    #[test]
    fn display_link() {
        let e =
            TraceEvent::link_created(22, Time::ZERO, 200, task(1), region(2), task(3), region(4));
        let s = format!("{e}");
        assert!(s.contains("link_ref=200"), "expected ref in {s}");
    }

    #[test]
    fn display_exit() {
        let e = TraceEvent::exit_delivered(
            23,
            Time::ZERO,
            200,
            task(1),
            task(3),
            Time::from_nanos(999),
            DownReason::Normal,
        );
        let s = format!("{e}");
        assert!(s.contains("exit"), "expected exit in {s}");
        assert!(s.contains("link_ref=200"), "expected ref in {s}");
    }

    #[test]
    fn display_message() {
        let e = TraceEvent::user_trace(24, Time::ZERO, "hello world");
        let s = format!("{e}");
        assert!(s.contains("\"hello world\""), "expected msg in {s}");
    }

    #[test]
    fn display_chaos_with_task() {
        let e = TraceEvent::new(
            25,
            Time::ZERO,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "delay".into(),
                task: Some(task(1)),
                detail: "200ns".into(),
            },
        );
        let s = format!("{e}");
        assert!(s.contains("chaos:delay"), "expected kind in {s}");
        assert!(s.contains("task="), "expected task in {s}");
        assert!(s.contains("200ns"), "expected detail in {s}");
    }

    #[test]
    fn display_chaos_without_task() {
        let e = TraceEvent::new(
            26,
            Time::ZERO,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "budget_exhaust".into(),
                task: None,
                detail: "all".into(),
            },
        );
        let s = format!("{e}");
        assert!(s.contains("chaos:budget_exhaust"), "expected kind in {s}");
        assert!(!s.contains("task="), "should not show task: {s}");
    }

    #[test]
    fn display_none_data() {
        let e = TraceEvent::new(27, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        let s = format!("{e}");
        // Should have seq, time, kind but nothing else
        assert!(s.contains("user_trace"), "expected kind in {s}");
    }

    #[test]
    fn display_with_logical_time() {
        let lt = LogicalTime::Lamport(LamportTime::from_raw(42));
        let e = TraceEvent::new(28, Time::ZERO, TraceEventKind::UserTrace, TraceData::None)
            .with_logical_time(lt);
        let s = format!("{e}");
        assert!(s.contains('@'), "expected @lt in {s}");
    }

    // ── Equality and Clone ─────────────────────────────────────────

    #[test]
    fn events_equal_same_fields() {
        let a = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let b = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        assert_eq!(a, b);
    }

    #[test]
    fn events_differ_on_seq() {
        let a = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let b = TraceEvent::spawn(2, Time::ZERO, task(1), region(2));
        assert_ne!(a, b);
    }

    #[test]
    fn events_differ_on_kind() {
        let a = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let b = TraceEvent::schedule(1, Time::ZERO, task(1), region(2));
        assert_ne!(a, b);
    }

    #[test]
    fn events_differ_on_data() {
        let a = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let b = TraceEvent::spawn(1, Time::ZERO, task(1), region(3));
        assert_ne!(a, b);
    }

    #[test]
    fn trace_data_clone() {
        let data = TraceData::Task {
            task: task(1),
            region: region(2),
        };
        let cloned = data.clone();
        assert_eq!(data, cloned);
    }

    #[test]
    fn trace_data_message_eq() {
        let a = TraceData::Message("hello".into());
        let b = TraceData::Message("hello".into());
        assert_eq!(a, b);
    }

    #[test]
    fn trace_data_message_ne() {
        let a = TraceData::Message("hello".into());
        let b = TraceData::Message("world".into());
        assert_ne!(a, b);
    }

    #[test]
    fn trace_data_none_variant() {
        assert_eq!(TraceData::None, TraceData::None);
    }

    #[test]
    fn trace_event_clone() {
        let e = TraceEvent::spawn(1, Time::ZERO, task(1), region(2));
        let c = e.clone();
        assert_eq!(e, c);
    }

    // ── Obligation all-kinds coverage ──────────────────────────────

    #[test]
    fn obligation_reserve_all_kinds() {
        for kind in [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
        ] {
            let e = TraceEvent::obligation_reserve(
                1,
                Time::ZERO,
                obligation(1),
                task(2),
                region(3),
                kind,
            );
            match &e.data {
                TraceData::Obligation { kind: k, .. } => assert_eq!(*k, kind),
                _ => panic!("wrong variant"),
            }
        }
    }

    #[test]
    fn obligation_abort_all_reasons() {
        for reason in [
            ObligationAbortReason::Cancel,
            ObligationAbortReason::Error,
            ObligationAbortReason::Explicit,
        ] {
            let e = TraceEvent::obligation_abort(
                1,
                Time::ZERO,
                obligation(1),
                task(2),
                region(3),
                ObligationKind::SendPermit,
                1000,
                reason,
            );
            match &e.data {
                TraceData::Obligation { abort_reason, .. } => {
                    assert_eq!(*abort_reason, Some(reason));
                }
                _ => panic!("wrong variant"),
            }
        }
    }

    // ── Down with error variant ────────────────────────────────────

    #[test]
    fn down_delivered_with_error_reason() {
        let e = TraceEvent::down_delivered(
            1,
            Time::ZERO,
            50,
            task(1),
            task(2),
            Time::from_nanos(100),
            DownReason::Error("boom".into()),
        );
        match &e.data {
            TraceData::Down { reason, .. } => {
                assert_eq!(*reason, DownReason::Error("boom".into()));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn exit_delivered_with_cancelled_reason() {
        let e = TraceEvent::exit_delivered(
            1,
            Time::ZERO,
            50,
            task(1),
            task(2),
            Time::from_nanos(100),
            DownReason::Cancelled(CancelReason::timeout()),
        );
        match &e.data {
            TraceData::Exit { reason, .. } => {
                assert!(matches!(reason, DownReason::Cancelled(_)));
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── Edge cases ─────────────────────────────────────────────────

    #[test]
    fn seq_zero() {
        let e = TraceEvent::new(0, Time::ZERO, TraceEventKind::UserTrace, TraceData::None);
        assert_eq!(e.seq, 0);
    }

    #[test]
    fn seq_max() {
        let e = TraceEvent::new(
            u64::MAX,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        );
        assert_eq!(e.seq, u64::MAX);
    }

    #[test]
    fn time_max() {
        let e = TraceEvent::new(1, Time::MAX, TraceEventKind::UserTrace, TraceData::None);
        assert_eq!(e.time, Time::MAX);
    }

    #[test]
    fn io_result_zero_bytes() {
        let e = TraceEvent::io_result(1, Time::ZERO, 0, 0);
        assert_eq!(e.data, TraceData::IoResult { token: 0, bytes: 0 });
    }

    #[test]
    fn checkpoint_zero_counts() {
        let e = TraceEvent::checkpoint(1, Time::ZERO, 0, 0, 0);
        assert_eq!(
            e.data,
            TraceData::Checkpoint {
                sequence: 0,
                active_tasks: 0,
                active_regions: 0
            }
        );
    }

    #[test]
    fn futurelock_many_held() {
        let held: Vec<_> = (0..100)
            .map(|i| (obligation(i), ObligationKind::SendPermit))
            .collect();
        let e = TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::FuturelockDetected,
            TraceData::Futurelock {
                task: task(1),
                region: region(2),
                idle_steps: 1000,
                held,
            },
        );
        let s = format!("{e}");
        // Should contain all 100 entries
        assert!(s.matches("SendPermit").count() == 100);
    }

    // --- wave 78 trait coverage ---

    #[test]
    fn trace_event_kind_debug_clone_copy_eq_ord_hash() {
        use std::collections::HashSet;
        let k = TraceEventKind::Spawn;
        let k2 = k; // Copy
        let k3 = k;
        assert_eq!(k, k2);
        assert_eq!(k, k3);
        assert_ne!(k, TraceEventKind::Complete);
        assert!(k < TraceEventKind::Complete);
        let dbg = format!("{k:?}");
        assert!(dbg.contains("Spawn"));
        let mut set = HashSet::new();
        set.insert(k);
        assert!(set.contains(&k2));
    }

    #[test]
    fn trace_data_debug_clone_eq() {
        let d = TraceData::None;
        let d2 = d.clone();
        assert_eq!(d, d2);
        assert_ne!(d, TraceData::Message("hi".into()));
        let dbg = format!("{d:?}");
        assert!(dbg.contains("None"));
    }

    #[test]
    fn trace_event_debug_clone_eq() {
        let e = TraceEvent::new(
            0,
            Time::from_nanos(100),
            TraceEventKind::UserTrace,
            TraceData::Message("hello".into()),
        );
        let e2 = e.clone();
        assert_eq!(e, e2);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("TraceEvent"));
    }

    #[test]
    fn browser_trace_schema_v1_validates() {
        let schema = browser_trace_schema_v1();
        validate_browser_trace_schema(&schema).expect("browser schema should validate");
    }

    #[test]
    fn browser_trace_schema_round_trip_json() {
        let schema = browser_trace_schema_v1();
        let payload = serde_json::to_string(&schema).expect("serialize schema");
        let decoded = decode_browser_trace_schema(&payload).expect("decode schema");
        assert_eq!(schema, decoded);
    }

    #[test]
    fn browser_trace_schema_timer_required_fields_match_payload_shape() {
        let schema = browser_trace_schema_v1();
        let scheduled = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "timer_scheduled")
            .expect("timer_scheduled entry should exist");
        let fired = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "timer_fired")
            .expect("timer_fired entry should exist");
        let cancelled = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "timer_cancelled")
            .expect("timer_cancelled entry should exist");

        assert_eq!(
            scheduled.required_fields,
            vec!["deadline".to_string(), "timer_id".to_string()]
        );
        assert_eq!(fired.required_fields, vec!["timer_id".to_string()]);
        assert_eq!(cancelled.required_fields, vec!["timer_id".to_string()]);
    }

    #[test]
    fn browser_trace_schema_obligation_required_fields_match_payload_shape() {
        let schema = browser_trace_schema_v1();
        let reserve = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "obligation_reserve")
            .expect("obligation_reserve entry should exist");
        let commit = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "obligation_commit")
            .expect("obligation_commit entry should exist");
        let abort = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "obligation_abort")
            .expect("obligation_abort entry should exist");
        let leak = schema
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "obligation_leak")
            .expect("obligation_leak entry should exist");

        assert_eq!(
            reserve.required_fields,
            vec![
                "kind".to_string(),
                "obligation".to_string(),
                "region".to_string(),
                "state".to_string(),
                "task".to_string(),
            ]
        );
        assert_eq!(
            commit.required_fields,
            vec![
                "duration_ns".to_string(),
                "kind".to_string(),
                "obligation".to_string(),
                "region".to_string(),
                "state".to_string(),
                "task".to_string(),
            ]
        );
        assert_eq!(
            abort.required_fields,
            vec![
                "abort_reason".to_string(),
                "duration_ns".to_string(),
                "kind".to_string(),
                "obligation".to_string(),
                "region".to_string(),
                "state".to_string(),
                "task".to_string(),
            ]
        );
        assert_eq!(
            leak.required_fields,
            vec![
                "duration_ns".to_string(),
                "kind".to_string(),
                "obligation".to_string(),
                "region".to_string(),
                "state".to_string(),
                "task".to_string(),
            ]
        );
    }

    #[test]
    fn browser_trace_schema_worker_required_fields_match_payload_shape() {
        let schema = browser_trace_schema_v1();
        for event_kind in [
            "worker_cancel_requested",
            "worker_cancel_acknowledged",
            "worker_drain_started",
            "worker_drain_completed",
            "worker_finalize_completed",
        ] {
            let entry = schema
                .event_specs
                .iter()
                .find(|entry| entry.event_kind == event_kind)
                .unwrap_or_else(|| panic!("{event_kind} entry should exist"));
            assert_eq!(entry.category, BrowserTraceCategory::CancellationTransition);
            assert_eq!(
                entry.required_fields,
                vec![
                    "decision_seq".to_string(),
                    "job_id".to_string(),
                    "obligation".to_string(),
                    "region".to_string(),
                    "replay_hash".to_string(),
                    "task".to_string(),
                    "worker_id".to_string(),
                ]
            );
        }
    }

    #[test]
    fn browser_trace_schema_decode_v0_migrates() {
        let legacy = serde_json::json!({
            "schema_version": "browser-trace-schema-v0",
            "required_envelope_fields": [
                "event_kind",
                "schema_version",
                "seq",
                "time_ns",
                "trace_id"
            ],
            "ordering_semantics": [
                "events must be strictly ordered by seq ascending",
                "logical_time must be monotonic for comparable causal domains",
                "trace streams must be deterministic for identical seed/config/replay inputs"
            ],
            "event_specs": browser_trace_schema_v1().event_specs
        });
        let payload = serde_json::to_string(&legacy).expect("serialize legacy schema");
        let decoded = decode_browser_trace_schema(&payload).expect("decode legacy schema");
        assert_eq!(
            decoded.schema_version,
            BROWSER_TRACE_SCHEMA_VERSION.to_string()
        );
        assert!(
            decoded
                .compatibility
                .backward_decode_aliases
                .iter()
                .any(|alias| alias == "browser-trace-schema-v0")
        );
    }

    #[test]
    fn browser_trace_schema_decode_v0_sparse_event_specs_use_defaults() {
        let event_specs = TraceEventKind::ALL
            .iter()
            .map(|kind| serde_json::json!({ "event_kind": kind.stable_name() }))
            .collect::<Vec<_>>();
        let legacy = serde_json::json!({
            "schema_version": "browser-trace-schema-v0",
            "required_envelope_fields": [
                "event_kind",
                "schema_version",
                "seq",
                "time_ns",
                "trace_id"
            ],
            "ordering_semantics": [
                "events must be strictly ordered by seq ascending",
                "logical_time must be monotonic for comparable causal domains",
                "trace streams must be deterministic for identical seed/config/replay inputs"
            ],
            "event_specs": event_specs
        });
        let payload = serde_json::to_string(&legacy).expect("serialize sparse legacy schema");
        let decoded = decode_browser_trace_schema(&payload).expect("decode sparse legacy schema");

        let user_trace = decoded
            .event_specs
            .iter()
            .find(|entry| entry.event_kind == "user_trace")
            .expect("user_trace entry should exist");
        assert_eq!(user_trace.category, BrowserTraceCategory::HostCallback);
        assert_eq!(user_trace.required_fields, vec!["message".to_string()]);
        assert_eq!(user_trace.redacted_fields, vec!["message".to_string()]);
    }

    #[test]
    fn browser_trace_schema_decode_v0_unknown_event_kind_fails_closed() {
        let legacy = serde_json::json!({
            "schema_version": "browser-trace-schema-v0",
            "required_envelope_fields": [
                "event_kind",
                "schema_version",
                "seq",
                "time_ns",
                "trace_id"
            ],
            "ordering_semantics": [
                "events must be strictly ordered by seq ascending",
                "logical_time must be monotonic for comparable causal domains",
                "trace streams must be deterministic for identical seed/config/replay inputs"
            ],
            "event_specs": [{ "event_kind": "not_a_real_event_kind" }]
        });
        let payload = serde_json::to_string(&legacy).expect("serialize invalid legacy schema");
        let error = decode_browser_trace_schema(&payload)
            .expect_err("unknown legacy event kinds must fail decode");
        assert!(error.contains("unknown legacy event kind"));
    }

    #[test]
    fn browser_trace_redaction_masks_message_payloads() {
        let event = TraceEvent::user_trace(4, Time::ZERO, "secret-token");
        let redacted = redact_browser_trace_event(&event);
        assert_eq!(
            redacted,
            TraceEvent::new(
                4,
                Time::ZERO,
                TraceEventKind::UserTrace,
                TraceData::Message("<redacted>".to_string())
            )
        );
    }

    // br-asupersync-92qzak: redact_browser_trace_event must scrub
    // free-form String payloads inside Cancel.reason.message,
    // RegionCancel.reason.message, Worker.worker_id, Down.reason
    // (Error / Cancelled / Panicked variants), and Exit.reason.
    // Pre-fix only UserTrace and ChaosInjection were redacted; this
    // test pins the new total coverage.
    #[test]
    fn redact_scrubs_cancel_reason_message_92qzak() {
        let task = TaskId::new_for_test(0, 1);
        let region = RegionId::new_for_test(0, 1);
        let reason = crate::types::CancelReason::user("invalid token sk_live_ABC123");
        let mut event = TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::CancelRequest,
            TraceData::Cancel {
                task,
                region,
                reason,
            },
        );
        // Touch the field so the warning about "_ unused" doesn't bite.
        event.seq = 1;
        let redacted = redact_browser_trace_event(&event);
        match &redacted.data {
            TraceData::Cancel { reason, .. } => {
                assert_eq!(reason.message.as_deref(), Some("<redacted>"));
            }
            other => panic!("expected redacted Cancel, got {other:?}"),
        }
    }

    #[test]
    fn redact_scrubs_region_cancel_reason_message_92qzak() {
        let region = RegionId::new_for_test(0, 1);
        let reason = crate::types::CancelReason::user("internal-secret");
        let event = TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::RegionCancelled,
            TraceData::RegionCancel { region, reason },
        );
        let redacted = redact_browser_trace_event(&event);
        match &redacted.data {
            TraceData::RegionCancel { reason, .. } => {
                assert_eq!(reason.message.as_deref(), Some("<redacted>"));
            }
            other => panic!("expected redacted RegionCancel, got {other:?}"),
        }
    }

    #[test]
    fn redact_scrubs_worker_id_92qzak() {
        let task = TaskId::new_for_test(0, 1);
        let region = RegionId::new_for_test(0, 1);
        let obligation = ObligationId::new_for_test(0, 1);
        let event = TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::ChaosInjection,
            TraceData::Worker {
                worker_id: "worker-with-secret-suffix-token-abc".to_string(),
                job_id: 42,
                decision_seq: 7,
                replay_hash: 0xdeadbeef,
                task,
                region,
                obligation,
            },
        );
        let redacted = redact_browser_trace_event(&event);
        match &redacted.data {
            TraceData::Worker { worker_id, .. } => assert_eq!(worker_id, "<redacted>"),
            other => panic!("expected redacted Worker, got {other:?}"),
        }
    }

    #[test]
    fn redact_scrubs_down_reason_error_string_92qzak() {
        let watcher = TaskId::new_for_test(0, 1);
        let monitored = TaskId::new_for_test(0, 2);
        let event = TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::ChaosInjection,
            TraceData::Down {
                monitor_ref: 1,
                watcher,
                monitored,
                completion_vt: Time::ZERO,
                reason: crate::monitor::DownReason::Error(
                    "/etc/secret_path:42 panicked with bearer eyJ...".to_string(),
                ),
            },
        );
        let redacted = redact_browser_trace_event(&event);
        match &redacted.data {
            TraceData::Down { reason, .. } => match reason {
                crate::monitor::DownReason::Error(msg) => assert_eq!(msg, "<redacted>"),
                other => panic!("expected Error variant, got {other:?}"),
            },
            other => panic!("expected redacted Down, got {other:?}"),
        }
    }

    #[test]
    fn redact_preserves_structural_identifiers_92qzak() {
        // Structural fields (TaskId, RegionId, sequence, kinds) MUST
        // be preserved so causality reconstruction is still possible
        // browser-side after redaction.
        let task = TaskId::new_for_test(0, 1);
        let region = RegionId::new_for_test(0, 1);
        let event = TraceEvent::new(
            42,
            Time::from_nanos(1234),
            TraceEventKind::Spawn,
            TraceData::Task { task, region },
        );
        let redacted = redact_browser_trace_event(&event);
        assert_eq!(redacted.seq, 42);
        assert_eq!(redacted.time, Time::from_nanos(1234));
        match &redacted.data {
            TraceData::Task { task: t, region: r } => {
                assert_eq!(*t, task);
                assert_eq!(*r, region);
            }
            other => panic!("expected Task data, got {other:?}"),
        }
    }

    #[test]
    fn browser_trace_log_fields_include_required_metadata() {
        let event = TraceEvent::timer_fired(9, Time::from_nanos(42), 10);
        let fields = browser_trace_log_fields(&event, "trace-browser-1", None);

        assert_eq!(
            fields.get("schema_version"),
            Some(&BROWSER_TRACE_SCHEMA_VERSION.to_string())
        );
        assert_eq!(fields.get("trace_id"), Some(&"trace-browser-1".to_string()));
        assert_eq!(fields.get("event_kind"), Some(&"timer_fired".to_string()));
        assert_eq!(fields.get("seq"), Some(&"9".to_string()));
        assert_eq!(fields.get("capture_source"), Some(&"runtime".to_string()));
        assert_eq!(fields.get("capture_host_turn_seq"), Some(&"9".to_string()));
        assert_eq!(fields.get("capture_source_seq"), Some(&"9".to_string()));
        assert_eq!(fields.get("capture_host_time_ns"), Some(&"42".to_string()));
        assert_eq!(
            fields.get("capture_replay_key"),
            Some(&"runtime:9:9:42".to_string())
        );
        assert_eq!(fields.get("validation_status"), Some(&"valid".to_string()));
        assert_eq!(
            fields.get("validation_failure_category"),
            Some(&"none".to_string())
        );
        assert_eq!(fields.get("sequence_group"), Some(&"timer:10".to_string()));
        assert_eq!(fields.get("timer_id"), Some(&"10".to_string()));
    }

    #[test]
    fn browser_trace_log_fields_with_capture_include_host_metadata() {
        let event = TraceEvent::timer_fired(17, Time::from_nanos(200), 11);
        let capture = BrowserCaptureMetadata {
            host_turn_seq: 71,
            source: BrowserCaptureSource::HostInput,
            source_seq: 4,
            host_time_ns: 9_001,
        };
        let fields =
            browser_trace_log_fields_with_capture(&event, "trace-browser-2", None, Some(&capture));
        assert_eq!(
            fields.get("capture_source"),
            Some(&"host_input".to_string())
        );
        assert_eq!(fields.get("capture_host_turn_seq"), Some(&"71".to_string()));
        assert_eq!(fields.get("capture_source_seq"), Some(&"4".to_string()));
        assert_eq!(
            fields.get("capture_host_time_ns"),
            Some(&"9001".to_string())
        );
        assert_eq!(
            fields.get("capture_replay_key"),
            Some(&"host_input:71:4:9001".to_string())
        );
    }

    #[test]
    fn browser_trace_log_fields_sequence_group_tracks_causal_domain() {
        let first = TraceEvent::timer_fired(7, Time::from_nanos(10), 41);
        let second = TraceEvent::timer_cancelled(8, Time::from_nanos(11), 41);
        let unrelated = TraceEvent::timer_fired(9, Time::from_nanos(12), 99);

        let first_fields = browser_trace_log_fields(&first, "trace-browser-group-1", None);
        let second_fields = browser_trace_log_fields(&second, "trace-browser-group-2", None);
        let unrelated_fields = browser_trace_log_fields(&unrelated, "trace-browser-group-3", None);

        assert_eq!(
            first_fields.get("sequence_group"),
            Some(&"timer:41".to_string())
        );
        assert_eq!(
            first_fields.get("sequence_group"),
            second_fields.get("sequence_group")
        );
        assert_ne!(
            first_fields.get("sequence_group"),
            unrelated_fields.get("sequence_group")
        );
    }

    #[test]
    fn browser_trace_log_fields_sequence_group_preserves_link_relationships() {
        let created = TraceEvent::link_created(
            20,
            Time::from_nanos(100),
            77,
            task(1),
            region(2),
            task(3),
            region(4),
        );
        let exited = TraceEvent::exit_delivered(
            21,
            Time::from_nanos(101),
            77,
            task(1),
            task(3),
            Time::from_nanos(55),
            DownReason::Normal,
        );
        let other = TraceEvent::link_dropped(
            22,
            Time::from_nanos(102),
            88,
            task(1),
            region(2),
            task(3),
            region(4),
        );

        let created_fields = browser_trace_log_fields(&created, "trace-browser-link-1", None);
        let exited_fields = browser_trace_log_fields(&exited, "trace-browser-link-2", None);
        let other_fields = browser_trace_log_fields(&other, "trace-browser-link-3", None);

        assert_eq!(
            created_fields.get("sequence_group"),
            Some(&"link:77".to_string())
        );
        assert_eq!(
            created_fields.get("sequence_group"),
            exited_fields.get("sequence_group")
        );
        assert_ne!(
            created_fields.get("sequence_group"),
            other_fields.get("sequence_group")
        );
    }

    #[test]
    fn browser_trace_log_fields_mark_invalid_when_failure_category_is_set() {
        let event = TraceEvent::timer_fired(9, Time::from_nanos(42), 10);
        let fields =
            browser_trace_log_fields(&event, "trace-browser-1", Some("schema_version_mismatch"));
        assert_eq!(
            fields.get("validation_status"),
            Some(&"invalid".to_string())
        );
        assert_eq!(
            fields.get("validation_failure_category"),
            Some(&"schema_version_mismatch".to_string())
        );
    }

    #[test]
    fn browser_trace_log_fields_redact_worker_identity_while_preserving_replay_linkage() {
        let raw_worker_id = "worker-a";
        let event = TraceEvent::worker_cancel_requested(
            21,
            Time::from_nanos(55),
            raw_worker_id,
            77,
            91,
            0x00C0_FFEE,
            task(9),
            region(10),
            obligation(11),
        );
        let fields = browser_trace_log_fields(&event, "trace-browser-worker-1", None);
        assert_eq!(fields.get("decision_seq"), Some(&"91".to_string()));
        assert_eq!(fields.get("job_id"), Some(&"77".to_string()));
        assert_eq!(fields.get("obligation"), Some(&obligation(11).to_string()));
        assert_eq!(fields.get("region"), Some(&region(10).to_string()));
        assert_eq!(fields.get("replay_hash"), Some(&"12648430".to_string()));
        assert_eq!(fields.get("task"), Some(&task(9).to_string()));
        assert_eq!(fields.get("worker_id"), Some(&"<redacted>".to_string()));
        assert_eq!(
            fields.get("sequence_group"),
            Some(&"worker_job:77:<redacted>".to_string())
        );
        assert!(
            fields.values().all(|value| !value.contains(raw_worker_id)),
            "browser trace log fields must not leak raw worker identity: {fields:?}"
        );
    }

    #[test]
    fn browser_trace_log_fields_snapshot_scrubs_ids_and_timestamps() {
        let event = TraceEvent::worker_cancel_requested(
            41,
            Time::from_nanos(123_456_789),
            "worker-browser-snapshot",
            88,
            17,
            0x00C0_FFEE,
            task(9),
            region(10),
            obligation(11),
        );
        let capture = BrowserCaptureMetadata {
            host_turn_seq: 7,
            source: BrowserCaptureSource::HostInput,
            source_seq: 19,
            host_time_ns: 1_726_133_456_789_000_000,
        };

        let fields = browser_trace_log_fields_with_capture(
            &event,
            "trace-browser-snapshot-1",
            None,
            Some(&capture),
        );

        insta::assert_json_snapshot!(
            "browser_trace_log_fields_worker_scrubbed",
            scrub_browser_trace_fields(&fields)
        );
    }

    #[test]
    fn browser_trace_log_fields_timer_snapshot_scrubs_ids_and_timestamps() {
        let event =
            TraceEvent::timer_scheduled(14, Time::from_nanos(333), 42, Time::from_nanos(999));
        let fields = browser_trace_log_fields(&event, "trace-browser-timer-1", None);

        insta::assert_json_snapshot!(
            "browser_trace_log_fields_timer_scrubbed",
            scrub_browser_trace_fields(&fields)
        );
    }

    #[test]
    fn browser_trace_log_fields_obligation_abort_snapshot_scrubs_ids_and_timestamps() {
        let event = TraceEvent::obligation_abort(
            52,
            Time::from_nanos(7_777),
            obligation(4),
            task(8),
            region(9),
            ObligationKind::Lease,
            5_000,
            ObligationAbortReason::Error,
        );
        let fields = browser_trace_log_fields(&event, "trace-browser-obligation-1", None);

        insta::assert_json_snapshot!(
            "browser_trace_log_fields_obligation_abort_scrubbed",
            scrub_browser_trace_fields(&fields)
        );
    }

    #[test]
    fn browser_trace_log_fields_exit_snapshot_scrubs_ids_and_timestamps() {
        let event = TraceEvent::exit_delivered(
            61,
            Time::from_nanos(8_001),
            77,
            task(2),
            task(3),
            Time::from_nanos(4_444),
            DownReason::Normal,
        );
        let fields = browser_trace_log_fields(&event, "trace-browser-exit-1", None);

        insta::assert_json_snapshot!(
            "browser_trace_log_fields_exit_scrubbed",
            scrub_browser_trace_fields(&fields)
        );
    }

    #[test]
    fn browser_trace_log_fields_redact_large_worker_attributes() {
        let raw_worker_id = format!("worker-{}", "e\u{0301}".repeat(200));
        let event = TraceEvent::worker_cancel_requested(
            30,
            Time::from_nanos(60),
            raw_worker_id.clone(),
            123,
            456,
            0xDEAD_BEEF,
            task(5),
            region(6),
            obligation(7),
        );
        let fields = browser_trace_log_fields(&event, "trace-browser-worker-2", None);

        let worker_id = fields
            .get("worker_id")
            .expect("worker_id field should be present");
        let sequence_group = fields
            .get("sequence_group")
            .expect("sequence_group field should be present");

        assert_eq!(worker_id, "<redacted>");
        assert_eq!(sequence_group, "worker_job:123:<redacted>");
        assert!(
            fields.values().all(|value| !value.contains(&raw_worker_id)),
            "browser trace log fields must not leak large raw worker identity: {fields:?}"
        );
    }

    #[test]
    fn browser_trace_attribute_cap_preserves_utf8_boundary() {
        let raw = format!("group:{}", "e\u{0301}".repeat(200));
        let capped = cap_browser_trace_attribute(&raw);

        assert!(capped.len() <= MAX_BROWSER_TRACE_ATTRIBUTE_BYTES);
        assert!(capped.starts_with("group:"));
        assert!(capped.contains('#'));
        assert!(capped.is_char_boundary(capped.len()));
    }

    // ── canonical serialization golden ─────────────────────────────
    //
    // Locks the on-the-wire JSON shape of `TraceEvent` across every
    // `TraceData` variant. Producers and consumers ride this wire
    // (recorder, replayer, browser bridge, distributed sheaf), so any
    // unintentional schema drift here is a cross-component breakage —
    // the snapshot is the firewall.

    #[test]
    fn trace_event_canonical_serialization_golden() {
        let events = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(0),
                TraceEventKind::UserTrace,
                TraceData::None,
            ),
            TraceEvent::spawn(2, Time::from_nanos(100), task(1), region(1)),
            TraceEvent::region_created(3, Time::from_nanos(200), region(2), Some(region(1))),
            TraceEvent::obligation_commit(
                4,
                Time::from_nanos(300),
                obligation(5),
                task(1),
                region(1),
                ObligationKind::Lease,
                1_500,
            ),
            TraceEvent::obligation_abort(
                5,
                Time::from_nanos(310),
                obligation(6),
                task(1),
                region(1),
                ObligationKind::SendPermit,
                2_500,
                ObligationAbortReason::Error,
            ),
            TraceEvent::cancel_request(
                6,
                Time::from_nanos(400),
                task(1),
                region(1),
                CancelReason::timeout(),
            ),
            TraceEvent::worker_cancel_requested(
                7,
                Time::from_nanos(500),
                "worker-canonical",
                42,
                7,
                0xDEAD_BEEF,
                task(1),
                region(1),
                obligation(2),
            ),
            TraceEvent::region_cancelled(
                8,
                Time::from_nanos(600),
                region(1),
                CancelReason::shutdown(),
            ),
            TraceEvent::time_advance(
                9,
                Time::from_nanos(700),
                Time::from_nanos(700),
                Time::from_nanos(800),
            ),
            TraceEvent::timer_scheduled(10, Time::from_nanos(800), 100, Time::from_nanos(900)),
            TraceEvent::timer_fired(11, Time::from_nanos(810), 100),
            TraceEvent::io_requested(12, Time::from_nanos(900), 7, 3),
            TraceEvent::io_ready(13, Time::from_nanos(1_000), 7, 1),
            TraceEvent::io_result(14, Time::from_nanos(1_100), 7, 4_096),
            TraceEvent::io_error(15, Time::from_nanos(1_200), 7, 5),
            TraceEvent::rng_seed(16, Time::from_nanos(1_300), 0x00C0_FFEE),
            TraceEvent::rng_value(17, Time::from_nanos(1_400), 42),
            TraceEvent::checkpoint(18, Time::from_nanos(1_500), 1_000, 5, 2),
            TraceEvent::new(
                19,
                Time::from_nanos(1_600),
                TraceEventKind::FuturelockDetected,
                TraceData::Futurelock {
                    task: task(2),
                    region: region(1),
                    idle_steps: 100,
                    held: vec![(obligation(3), ObligationKind::SendPermit)],
                },
            ),
            TraceEvent::monitor_created(
                20,
                Time::from_nanos(1_700),
                50,
                task(1),
                region(1),
                task(2),
            ),
            TraceEvent::down_delivered(
                21,
                Time::from_nanos(1_800),
                50,
                task(1),
                task(2),
                Time::from_nanos(1_750),
                DownReason::Normal,
            ),
            TraceEvent::link_created(
                22,
                Time::from_nanos(1_900),
                60,
                task(1),
                region(1),
                task(2),
                region(2),
            ),
            TraceEvent::exit_delivered(
                23,
                Time::from_nanos(2_000),
                60,
                task(1),
                task(2),
                Time::from_nanos(1_950),
                DownReason::Normal,
            ),
            TraceEvent::user_trace(24, Time::from_nanos(2_100), "canonical-trace-marker"),
            TraceEvent::new(
                25,
                Time::from_nanos(2_200),
                TraceEventKind::ChaosInjection,
                TraceData::Chaos {
                    kind: "delay".to_string(),
                    task: Some(task(1)),
                    detail: "injected 1ms delay".to_string(),
                },
            ),
            TraceEvent::poll(26, Time::from_nanos(2_300), task(1), region(1))
                .with_logical_time(LogicalTime::Lamport(LamportTime::from_raw(7))),
        ];

        // Round-trip every event back through Deserialize so the
        // golden also locks `TraceData` discriminant tags and field
        // names against accidental rename — a renamed field that
        // keeps the same JSON layout would still fail Deserialize.
        for event in &events {
            let json = serde_json::to_value(event).expect("serialize trace event");
            let decoded: TraceEvent =
                serde_json::from_value(json).expect("deserialize trace event");
            assert_eq!(*event, decoded, "round-trip mismatch for {event:?}");
        }

        insta::assert_json_snapshot!("trace_event_canonical_serialization", events);
    }

    /// Golden test for OpenTelemetry span-focused 5-event trace serialization.
    ///
    /// This test pins the canonical JSON serialization of a minimal 5-event
    /// trace representing a typical span lifecycle: spawn → schedule → poll →
    /// user trace → complete. The golden snapshot ensures that OpenTelemetry
    /// bridge exporters receive consistent trace event structure across runtime
    /// versions.
    #[test]
    fn otel_span_golden_tests() {
        let span_events = vec![
            // Span start: task spawned in a region
            TraceEvent::spawn(1, Time::from_nanos(1000), task(10), region(5)),
            // Task gets scheduled for execution
            TraceEvent::schedule(2, Time::from_nanos(1100), task(10), region(5)),
            // Task execution begins
            TraceEvent::poll(3, Time::from_nanos(1200), task(10), region(5)),
            // User trace event within the span
            TraceEvent::user_trace(4, Time::from_nanos(1250), "otel-span-processing"),
            // Span end: task completion
            TraceEvent::complete(5, Time::from_nanos(1300), task(10), region(5)),
        ];

        // Verify round-trip serialization integrity for OTel exports
        for event in &span_events {
            let json = serde_json::to_value(event).expect("serialize otel span event");
            let decoded: TraceEvent =
                serde_json::from_value(json).expect("deserialize otel span event");
            assert_eq!(
                *event, decoded,
                "otel span round-trip mismatch for {event:?}"
            );
        }

        insta::assert_json_snapshot!("otel_span_golden_tests", span_events);
    }

    /// Serialize trace events to canonical NDJSON format.
    ///
    /// Each event becomes a single JSON object on its own line, suitable for
    /// streaming trace ingestion and line-by-line processing pipelines.
    fn trace_events_to_ndjson(events: &[TraceEvent]) -> Result<String, serde_json::Error> {
        let mut ndjson = String::new();
        for event in events {
            let json_line = serde_json::to_string(event)?;
            ndjson.push_str(&json_line);
            ndjson.push('\n');
        }
        Ok(ndjson)
    }

    /// Golden test for canonical NDJSON trace event serialization.
    ///
    /// This test pins the NDJSON (Newline Delimited JSON) serialization format
    /// for trace events. Each event becomes a single JSON object per line,
    /// ensuring compatibility with streaming ingestion pipelines and
    /// line-oriented processing tools.
    #[test]
    fn trace_event_canonical_ndjson_serialization() {
        let ndjson_events = vec![
            // Simple task lifecycle for NDJSON streaming
            TraceEvent::spawn(1, Time::from_nanos(5000), task(20), region(10)),
            TraceEvent::schedule(2, Time::from_nanos(5100), task(20), region(10)),
            TraceEvent::poll(3, Time::from_nanos(5200), task(20), region(10)),
            TraceEvent::user_trace(4, Time::from_nanos(5250), "ndjson-stream-marker"),
            TraceEvent::complete(5, Time::from_nanos(5300), task(20), region(10)),
        ];

        // Generate canonical NDJSON format
        let ndjson_output =
            trace_events_to_ndjson(&ndjson_events).expect("NDJSON serialization should succeed");

        // Verify each line is valid JSON
        for (i, line) in ndjson_output.lines().enumerate() {
            if !line.is_empty() {
                let parsed: serde_json::Value = serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("Line {i} is not valid JSON: {e}"));
                assert!(parsed.is_object(), "Line {i} should be a JSON object");
            }
        }

        // Verify round-trip through NDJSON parsing
        let parsed_events: Result<Vec<TraceEvent>, _> = ndjson_output
            .lines()
            .filter(|line| !line.is_empty())
            .map(serde_json::from_str)
            .collect();
        let decoded_events = parsed_events.expect("NDJSON round-trip should succeed");
        assert_eq!(ndjson_events, decoded_events, "NDJSON round-trip mismatch");

        insta::assert_snapshot!("trace_event_canonical_ndjson_serialization", ndjson_output);
    }
